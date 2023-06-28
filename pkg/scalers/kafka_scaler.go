package scalers

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	kedautil "github.com/kedacore/keda/v2/pkg/util"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	v2 "k8s.io/api/autoscaling/v2"
	"k8s.io/metrics/pkg/apis/external_metrics"
)

type kafkaScaler struct {
	metricType      v2.MetricTargetType
	metadata        kafkaMetadata
	client          *kafka.Client
	transport       *kafka.Transport
	logger          logr.Logger
	previousOffsets map[string]map[int]int64
}

const (
	stringEnable  = "enable"
	stringDisable = "disable"
)

type kafkaMetadata struct {
	bootstrapServers       []string
	group                  string
	topic                  []string
	partitionLimitation    []int32
	lagThreshold           int64
	activationLagThreshold int64
	offsetResetPolicy      offsetResetPolicy
	allowIdleConsumers     bool
	excludePersistentLag   bool

	// If an invalid offset is found, whether to scale to 1 (false - the default) so consumption can
	// occur or scale to 0 (true). See discussion in https://github.com/kedacore/keda/issues/2612
	scaleToZeroOnInvalidOffset bool

	// SASL
	saslType kafkaSaslType
	username string
	password string

	// OAUTHBEARER
	scopes                []string
	oauthTokenEndpointURI string
	oauthExtensions       map[string]string

	// TLS
	enableTLS   bool
	cert        string
	key         string
	keyPassword string
	ca          string

	scalerIndex int
}

type offsetResetPolicy string

const (
	latest   offsetResetPolicy = "latest"
	earliest offsetResetPolicy = "earliest"
)

type kafkaSaslType string

// supported SASL types
const (
	KafkaSASLTypeNone        kafkaSaslType = "none"
	KafkaSASLTypePlaintext   kafkaSaslType = "plaintext"
	KafkaSASLTypeSCRAMSHA256 kafkaSaslType = "scram_sha256"
	KafkaSASLTypeSCRAMSHA512 kafkaSaslType = "scram_sha512"
	KafkaSASLTypeOAuthbearer kafkaSaslType = "oauthbearer"
)

const (
	lagThresholdMetricName             = "lagThreshold"
	activationLagThresholdMetricName   = "activationLagThreshold"
	kafkaMetricType                    = "External"
	defaultKafkaLagThreshold           = 10
	defaultKafkaActivationLagThreshold = 0
	defaultOffsetResetPolicy           = latest
	invalidOffset                      = -1
)

// NewKafkaScaler creates a new kafkaScaler
func NewKafkaScaler(config *ScalerConfig) (Scaler, error) {
	metricType, err := GetMetricTargetType(config)
	if err != nil {
		return nil, fmt.Errorf("error getting scaler metric type: %w", err)
	}

	logger := InitializeLogger(config, "kafka_scaler")

	kafkaMetadata, err := parseKafkaMetadata(config, logger)
	if err != nil {
		return nil, fmt.Errorf("error parsing kafka metadata: %w", err)
	}

	client, transport, err := getKafkaClients(kafkaMetadata)
	if err != nil {
		return nil, err
	}

	previousOffsets := make(map[string]map[int]int64)

	return &kafkaScaler{
		client:          client,
		transport:       transport,
		metricType:      metricType,
		metadata:        kafkaMetadata,
		logger:          logger,
		previousOffsets: previousOffsets,
	}, nil
}

func parseKafkaAuthParams(config *ScalerConfig, meta *kafkaMetadata) error {
	meta.saslType = KafkaSASLTypeNone
	var saslAuthType string
	switch {
	case config.TriggerMetadata["sasl"] != "":
		saslAuthType = config.TriggerMetadata["sasl"]
	default:
		saslAuthType = ""
	}
	if val, ok := config.AuthParams["sasl"]; ok {
		if saslAuthType != "" {
			return errors.New("unable to set `sasl` in both ScaledObject and TriggerAuthentication together")
		}
		saslAuthType = val
	}

	if saslAuthType != "" {
		saslAuthType = strings.TrimSpace(saslAuthType)
		mode := kafkaSaslType(saslAuthType)

		if mode == KafkaSASLTypePlaintext || mode == KafkaSASLTypeSCRAMSHA256 || mode == KafkaSASLTypeSCRAMSHA512 || mode == KafkaSASLTypeOAuthbearer {
			if config.AuthParams["username"] == "" {
				return errors.New("no username given")
			}
			meta.username = strings.TrimSpace(config.AuthParams["username"])

			if config.AuthParams["password"] == "" {
				return errors.New("no password given")
			}
			meta.password = strings.TrimSpace(config.AuthParams["password"])
			meta.saslType = mode

			if mode == KafkaSASLTypeOAuthbearer {
				meta.scopes = strings.Split(config.AuthParams["scopes"], ",")

				if config.AuthParams["oauthTokenEndpointUri"] == "" {
					return errors.New("no oauth token endpoint uri given")
				}
				meta.oauthTokenEndpointURI = strings.TrimSpace(config.AuthParams["oauthTokenEndpointUri"])

				meta.oauthExtensions = make(map[string]string)
				oauthExtensionsRaw := config.AuthParams["oauthExtensions"]
				if oauthExtensionsRaw != "" {
					for _, extension := range strings.Split(oauthExtensionsRaw, ",") {
						splittedExtension := strings.Split(extension, "=")
						if len(splittedExtension) != 2 {
							return errors.New("invalid OAuthBearer extension, must be of format key=value")
						}
						meta.oauthExtensions[splittedExtension[0]] = splittedExtension[1]
					}
				}
			}
		} else {
			return fmt.Errorf("err SASL mode %s given", mode)
		}
	}

	meta.enableTLS = false
	enableTLS := false
	if val, ok := config.TriggerMetadata["tls"]; ok {
		switch val {
		case stringEnable:
			enableTLS = true
		case stringDisable:
			enableTLS = false
		default:
			return fmt.Errorf("error incorrect TLS value given, got %s", val)
		}
	}

	if val, ok := config.AuthParams["tls"]; ok {
		val = strings.TrimSpace(val)
		if enableTLS {
			return errors.New("unable to set `tls` in both ScaledObject and TriggerAuthentication together")
		}
		switch val {
		case stringEnable:
			enableTLS = true
		case stringDisable:
			enableTLS = false
		default:
			return fmt.Errorf("error incorrect TLS value given, got %s", val)
		}
	}

	if enableTLS {
		certGiven := config.AuthParams["cert"] != ""
		keyGiven := config.AuthParams["key"] != ""
		if certGiven && !keyGiven {
			return errors.New("key must be provided with cert")
		}
		if keyGiven && !certGiven {
			return errors.New("cert must be provided with key")
		}
		meta.ca = config.AuthParams["ca"]
		meta.cert = config.AuthParams["cert"]
		meta.key = config.AuthParams["key"]
		if value, found := config.AuthParams["keyPassword"]; found {
			meta.keyPassword = value
		} else {
			meta.keyPassword = ""
		}
		meta.enableTLS = true
	}

	return nil
}

func parseKafkaMetadata(config *ScalerConfig, logger logr.Logger) (kafkaMetadata, error) {
	meta := kafkaMetadata{}
	switch {
	case config.TriggerMetadata["bootstrapServersFromEnv"] != "":
		meta.bootstrapServers = strings.Split(config.ResolvedEnv[config.TriggerMetadata["bootstrapServersFromEnv"]], ",")
	case config.TriggerMetadata["bootstrapServers"] != "":
		meta.bootstrapServers = strings.Split(config.TriggerMetadata["bootstrapServers"], ",")
	default:
		return meta, errors.New("no bootstrapServers given")
	}

	switch {
	case config.TriggerMetadata["consumerGroupFromEnv"] != "":
		meta.group = config.ResolvedEnv[config.TriggerMetadata["consumerGroupFromEnv"]]
	case config.TriggerMetadata["consumerGroup"] != "":
		meta.group = config.TriggerMetadata["consumerGroup"]
	default:
		return meta, errors.New("no consumer group given")
	}

	switch {
	case config.TriggerMetadata["topicFromEnv"] != "":
		meta.topic = strings.Split(config.ResolvedEnv[config.TriggerMetadata["topicFromEnv"]], ",")
	case config.TriggerMetadata["topic"] != "":
		meta.topic = strings.Split(config.TriggerMetadata["topic"], ",")
	default:
		meta.topic = []string{}
		logger.V(1).Info(fmt.Sprintf("consumer group %q has no topic specified, "+
			"will use all topics subscribed by the consumer group for scaling", meta.group))
	}

	meta.partitionLimitation = nil
	partitionLimitationMetadata := strings.TrimSpace(config.TriggerMetadata["partitionLimitation"])
	if partitionLimitationMetadata != "" {
		if meta.topic == nil || len(meta.topic) == 0 {
			logger.V(1).Info("no specific topic set, ignoring partitionLimitation setting")
		} else {
			pattern := config.TriggerMetadata["partitionLimitation"]
			parsed, err := kedautil.ParseInt32List(pattern)
			if err != nil {
				return meta, fmt.Errorf("error parsing in partitionLimitation '%s': %w", pattern, err)
			}
			meta.partitionLimitation = parsed
			logger.V(0).Info(fmt.Sprintf("partition limit active '%s'", pattern))
		}
	}

	meta.offsetResetPolicy = defaultOffsetResetPolicy

	if config.TriggerMetadata["offsetResetPolicy"] != "" {
		policy := offsetResetPolicy(config.TriggerMetadata["offsetResetPolicy"])
		if policy != earliest && policy != latest {
			return meta, fmt.Errorf("err offsetResetPolicy policy %q given", policy)
		}
		meta.offsetResetPolicy = policy
	}

	meta.lagThreshold = defaultKafkaLagThreshold

	if val, ok := config.TriggerMetadata[lagThresholdMetricName]; ok {
		t, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return meta, fmt.Errorf("error parsing %q: %w", lagThresholdMetricName, err)
		}
		if t <= 0 {
			return meta, fmt.Errorf("%q must be positive number", lagThresholdMetricName)
		}
		meta.lagThreshold = t
	}

	meta.activationLagThreshold = defaultKafkaActivationLagThreshold

	if val, ok := config.TriggerMetadata[activationLagThresholdMetricName]; ok {
		t, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return meta, fmt.Errorf("error parsing %q: %w", activationLagThresholdMetricName, err)
		}
		if t < 0 {
			return meta, fmt.Errorf("%q must be positive number", activationLagThresholdMetricName)
		}
		meta.activationLagThreshold = t
	}

	if err := parseKafkaAuthParams(config, &meta); err != nil {
		return meta, err
	}

	meta.allowIdleConsumers = false
	if val, ok := config.TriggerMetadata["allowIdleConsumers"]; ok {
		t, err := strconv.ParseBool(val)
		if err != nil {
			return meta, fmt.Errorf("error parsing allowIdleConsumers: %w", err)
		}
		meta.allowIdleConsumers = t
	}

	meta.excludePersistentLag = false
	if val, ok := config.TriggerMetadata["excludePersistentLag"]; ok {
		t, err := strconv.ParseBool(val)
		if err != nil {
			return meta, fmt.Errorf("error parsing excludePersistentLag: %w", err)
		}
		meta.excludePersistentLag = t
	}

	meta.scaleToZeroOnInvalidOffset = false
	if val, ok := config.TriggerMetadata["scaleToZeroOnInvalidOffset"]; ok {
		t, err := strconv.ParseBool(val)
		if err != nil {
			return meta, fmt.Errorf("error parsing scaleToZeroOnInvalidOffset: %w", err)
		}
		meta.scaleToZeroOnInvalidOffset = t
	}

	meta.scalerIndex = config.ScalerIndex
	return meta, nil
}

func getKafkaClients(metadata kafkaMetadata) (*kafka.Client, *kafka.Transport, error) {

	var saslMechanism sasl.Mechanism = nil
	var tlsConfig *tls.Config = nil
	var err error

	if metadata.saslType != KafkaSASLTypeNone {
		saslMechanism = plain.Mechanism{
			Username: metadata.username,
			Password: metadata.password,
		}
	}

	if metadata.enableTLS {
		tlsConfig, err = kedautil.NewTLSConfigWithPassword(metadata.cert, metadata.key, metadata.keyPassword, metadata.ca, false)
		if err != nil {
			return nil, nil, err
		}
	}

	if metadata.saslType == KafkaSASLTypePlaintext {
		saslMechanism = plain.Mechanism{
			Username: metadata.username,
			Password: metadata.password,
		}
	}

	if metadata.saslType == KafkaSASLTypeSCRAMSHA256 {
		saslMechanism, err = scram.Mechanism(scram.SHA256, metadata.username, metadata.password)
		if err != nil {
			return nil, nil, err
		}
	}

	if metadata.saslType == KafkaSASLTypeSCRAMSHA512 {
		saslMechanism, err = scram.Mechanism(scram.SHA512, metadata.username, metadata.password)
		if err != nil {
			return nil, nil, err
		}
	}

	if metadata.saslType == KafkaSASLTypeOAuthbearer {
		// TODO: implement
		return nil, nil, fmt.Errorf("SASL/OAUTHBEARER is not implemented yet")
	}

	transport := &kafka.Transport{
		TLS:  tlsConfig,
		SASL: saslMechanism,
	}
	client := kafka.Client{
		Addr:      kafka.TCP(metadata.bootstrapServers...),
		Transport: transport,
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error creating kafka client: %w", err)
	}

	return &client, transport, nil
}

func (s *kafkaScaler) listSubscribedTopics(resp *kafka.DescribeGroupsResponse) []string {
	var _topics []string
	for _, group := range resp.Groups {
		for _, member := range group.Members {
			_topics = append(_topics, member.MemberMetadata.Topics...)
		}
	}
	return _topics
}

func (s *kafkaScaler) getTopicPartitions() (map[string][]int, error) {

	dialer := &kafka.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		SASLMechanism: s.transport.SASL,
		TLS:           s.transport.TLS,
	}

	conn, err := dialer.Dial("tcp", s.metadata.bootstrapServers[0])

	if err != nil {
		return nil, fmt.Errorf("error dialing to kafka: %w", err)
	}
	defer func(conn *kafka.Conn) {
		if err := conn.Close(); err != nil {
			s.logger.Error(err, "error closing dialed connection %s", conn.RemoteAddr())
		}
	}(conn)

	var partitions []kafka.Partition

	var _topics []string

	if s.metadata.topic == nil || len(s.metadata.topic) == 0 {
		// when no topic is specified, fetch all _topics the consumer group is subscribed to
		describeResp, err := s.client.DescribeGroups(context.Background(), &kafka.DescribeGroupsRequest{
			GroupIDs: []string{s.metadata.group},
		})
		if err != nil || len(describeResp.Groups) == 0 || len(describeResp.Groups[0].Members) == 0 {
			// fallback to listing all _topics
			_topics = []string{}
		} else {
			_topics = s.listSubscribedTopics(describeResp)
		}
	} else {
		// when topic is specified, use that
		_topics = s.metadata.topic
	}
	partitions, err = conn.ReadPartitions(_topics...)
	if err != nil {
		return nil, fmt.Errorf("error reading partitions for topic %s: %w", s.metadata.topic, err)
	}

	// collect topic names
	topicPartitions := make(map[string][]int)
	for _, partition := range partitions {
		topicPartitions[partition.Topic] = append(topicPartitions[partition.Topic], partition.ID)
	}

	return topicPartitions, nil
}

func (s *kafkaScaler) isActivePartition(pID int32) bool {
	if s.metadata.partitionLimitation == nil {
		return true
	}
	for _, _pID := range s.metadata.partitionLimitation {
		if pID == _pID {
			return true
		}
	}
	return false
}

func (s *kafkaScaler) getConsumerOffsets(topicPartitions map[string][]int) (map[string]map[int]int64, error) {
	response, err := s.client.OffsetFetch(
		context.Background(),
		&kafka.OffsetFetchRequest{
			GroupID: s.metadata.group,
			Topics:  topicPartitions,
		},
	)
	if err != nil || response.Error != nil {
		return nil, fmt.Errorf("error listing consumer group offset: %w", err)
	}
	consumerOffset := make(map[string]map[int]int64)
	for topic, partitionsOffset := range response.Topics {
		consumerOffset[topic] = make(map[int]int64)
		for _, partition := range partitionsOffset {
			consumerOffset[topic][partition.Partition] = partition.CommittedOffset
		}
	}
	return consumerOffset, nil
}

/*
getLagForPartition returns (lag, lagWithPersistent, error)

When excludePersistentLag is set to `false` (default), lag will always be equal to lagWithPersistent
When excludePersistentLag is set to `true`, if partition is deemed to have persistent lag, lag will be set to 0 and lagWithPersistent will be latestOffset - consumerOffset
These return values will allow proper scaling from 0 -> 1 replicas by the IsActive func.
*/
func (s *kafkaScaler) getLagForPartition(topic string, partitionID int, consumerOffsets map[string]map[int]int64, producerOffsets map[string]map[int]int64) (int64, int64, error) {
	if consumerOffsets == nil || len(consumerOffsets) == 0 {
		return 0, 0, fmt.Errorf("consumerOffsets is empty")
	}
	if producerOffsets == nil || len(producerOffsets) == 0 {
		return 0, 0, fmt.Errorf("producerOffsets is empty")
	}

	consumerOffset := consumerOffsets[topic][partitionID]
	if consumerOffset == invalidOffset && s.metadata.offsetResetPolicy == latest {
		retVal := int64(1)
		if s.metadata.scaleToZeroOnInvalidOffset {
			retVal = 0
		}
		msg := fmt.Sprintf(
			"invalid offset found for topic %s in group %s and partition %d, probably no offset is committed yet. Returning with lag of %d",
			topic, s.metadata.group, partitionID, retVal)
		s.logger.V(1).Info(msg)
		return retVal, retVal, nil
	}

	if _, found := producerOffsets[topic]; !found {
		return 0, 0, fmt.Errorf("error finding partition offset for topic %s", topic)
	}
	producerOffset := producerOffsets[topic][partitionID]
	if consumerOffset == invalidOffset && s.metadata.offsetResetPolicy == earliest {
		return producerOffset, producerOffset, nil
	}

	// This code block tries to prevent KEDA Kafka trigger from scaling the scale target based on erroneous events
	if s.metadata.excludePersistentLag {
		switch previousOffset, found := s.previousOffsets[topic][partitionID]; {
		case !found:
			// No record of previous offset, so store current consumer offset
			// Allow this consumer lag to be considered in scaling
			if _, topicFound := s.previousOffsets[topic]; !topicFound {
				s.previousOffsets[topic] = map[int]int64{partitionID: consumerOffset}
			} else {
				s.previousOffsets[topic][partitionID] = consumerOffset
			}
		case previousOffset == consumerOffset:
			// Indicates consumer is still on the same offset as the previous polling cycle, there may be some issue with consuming this offset.
			// return 0, so this consumer lag is not considered for scaling
			return 0, producerOffset - consumerOffset, nil
		default:
			// Successfully Consumed some messages, proceed to change the previous offset
			s.previousOffsets[topic][partitionID] = consumerOffset
		}
	}

	return producerOffset - consumerOffset, producerOffset - consumerOffset, nil
}

// Close closes the kafka client
func (s *kafkaScaler) Close(context.Context) error {
	if s.client == nil {
		return nil
	}
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	//s.client = nil
	//s.transport = nil
	return nil
}

func (s *kafkaScaler) GetMetricSpecForScaling(context.Context) []v2.MetricSpec {
	var metricName string
	if s.metadata.topic != nil && len(s.metadata.topic) > 0 {
		metricName = fmt.Sprintf("kafka-%s", strings.Join(s.metadata.topic, ","))
	} else {
		metricName = fmt.Sprintf("kafka-%s-topics", s.metadata.group)
	}

	externalMetric := &v2.ExternalMetricSource{
		Metric: v2.MetricIdentifier{
			Name: GenerateMetricNameWithIndex(s.metadata.scalerIndex, kedautil.NormalizeString(metricName)),
		},
		Target: GetMetricTarget(s.metricType, s.metadata.lagThreshold),
	}
	metricSpec := v2.MetricSpec{External: externalMetric, Type: kafkaMetricType}
	return []v2.MetricSpec{metricSpec}
}

type consumerOffsetResult struct {
	consumerOffsets map[string]map[int]int64
	err             error
}

type producerOffsetResult struct {
	producerOffsets map[string]map[int]int64
	err             error
}

// getConsumerAndProducerOffsets returns (consumerOffsets, producerOffsets, error)
func (s *kafkaScaler) getConsumerAndProducerOffsets(topicPartitions map[string][]int) (map[string]map[int]int64, map[string]map[int]int64, error) {
	consumerChan := make(chan consumerOffsetResult, 1)
	go func() {
		consumerOffsets, err := s.getConsumerOffsets(topicPartitions)
		consumerChan <- consumerOffsetResult{consumerOffsets, err}
	}()

	producerChan := make(chan producerOffsetResult, 1)
	go func() {
		producerOffsets, err := s.getProducerOffsets(topicPartitions)
		producerChan <- producerOffsetResult{producerOffsets, err}
	}()

	consumerRes := <-consumerChan
	if consumerRes.err != nil {
		return nil, nil, consumerRes.err
	}

	producerRes := <-producerChan
	if producerRes.err != nil {
		return nil, nil, producerRes.err
	}

	return consumerRes.consumerOffsets, producerRes.producerOffsets, nil
}

// GetMetricsAndActivity returns value for a supported metric and an error if there is a problem getting the metric
func (s *kafkaScaler) GetMetricsAndActivity(_ context.Context, metricName string) ([]external_metrics.ExternalMetricValue, bool, error) {
	totalLag, totalLagWithPersistent, err := s.getTotalLag()
	if err != nil {
		return []external_metrics.ExternalMetricValue{}, false, err
	}
	metric := GenerateMetricInMili(metricName, float64(totalLag))

	return []external_metrics.ExternalMetricValue{metric}, totalLagWithPersistent > s.metadata.activationLagThreshold, nil
}

// getTotalLag returns totalLag, totalLagWithPersistent, error
// totalLag and totalLagWithPersistent are the summations of lag and lagWithPersistent returned by getLagForPartition function respectively.
// totalLag maybe less than totalLagWithPersistent when excludePersistentLag is set to `true` due to some partitions deemed as having persistent lag
func (s *kafkaScaler) getTotalLag() (int64, int64, error) {
	topicPartitions, err := s.getTopicPartitions()
	if err != nil {
		return 0, 0, err
	}

	consumerOffsets, producerOffsets, err := s.getConsumerAndProducerOffsets(topicPartitions)
	if err != nil {
		return 0, 0, err
	}

	totalLag := int64(0)
	totalLagWithPersistent := int64(0)
	totalTopicPartitions := int64(0)

	for topic, partitionsOffsets := range producerOffsets {
		for partition := range partitionsOffsets {
			lag, lagWithPersistent, err := s.getLagForPartition(topic, partition, consumerOffsets, producerOffsets)
			if err != nil {
				return 0, 0, err
			}
			totalLag += lag
			totalLagWithPersistent += lagWithPersistent
		}
		totalTopicPartitions += (int64)(len(partitionsOffsets))
	}
	s.logger.V(1).Info(fmt.Sprintf("Kafka scaler: Providing metrics based on totalLag %v, topicPartitions %v, threshold %v", totalLag, len(topicPartitions), s.metadata.lagThreshold))

	if !s.metadata.allowIdleConsumers {
		// don't scale out beyond the number of topicPartitions
		if (totalLag / s.metadata.lagThreshold) > totalTopicPartitions {
			totalLag = totalTopicPartitions * s.metadata.lagThreshold
		}
	}
	return totalLag, totalLagWithPersistent, nil
}

// getProducerOffsets returns the latest offsets for the given topic partitions
func (s *kafkaScaler) getProducerOffsets(topicPartitions map[string][]int) (map[string]map[int]int64, error) {
	// Step 1: build one OffsetRequest
	offsetRequest := make(map[string][]kafka.OffsetRequest)

	for topic, partitions := range topicPartitions {
		for _, partitionID := range partitions {
			offsetRequest[topic] = append(offsetRequest[topic], kafka.FirstOffsetOf(partitionID), kafka.LastOffsetOf(partitionID))
		}
	}

	// Step 2: send request
	res, err := s.client.ListOffsets(context.Background(), &kafka.ListOffsetsRequest{
		Topics: offsetRequest,
	})
	if err != nil {
		return nil, err
	}

	// Step 3: parse response and return
	producerOffsets := make(map[string]map[int]int64)
	for topic, partitionOffset := range res.Topics {
		producerOffsets[topic] = make(map[int]int64)
		for _, partition := range partitionOffset {
			producerOffsets[topic][partition.Partition] = partition.LastOffset
		}
	}

	return producerOffsets, nil
}
