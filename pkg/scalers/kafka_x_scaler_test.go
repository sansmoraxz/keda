package scalers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/go-logr/logr"
)

type parseKafkaXMetadataTestData struct {
	metadata             map[string]string
	isError              bool
	numBrokers           int
	brokers              []string
	group                string
	topic                []string
	partitionLimitation  []int32
	offsetResetPolicy    offsetResetPolicy
	allowIdleConsumers   bool
	excludePersistentLag bool
}

type parseKafkaXAuthParamsTestData struct {
	authParams map[string]string
	isError    bool
	enableTLS  bool
}

// Testing the case where `tls` and `sasl` are specified in ScaledObject
type parseKafkaXAuthParamsTestDataSecondAuthMethod struct {
	metadata   map[string]string
	authParams map[string]string
	isError    bool
	enableTLS  bool
}

type kafkaXMetricIdentifier struct {
	metadataTestData *parseKafkaXMetadataTestData
	scalerIndex      int
	name             string
}

// A complete valid metadata example for reference
var validKafkaXMetadata = map[string]string{
	"bootstrapServers":   "broker1:9092,broker2:9092",
	"consumerGroup":      "my-group",
	"topic":              "my-topics",
	"allowIdleConsumers": "false",
}

// A complete valid authParams example for sasl, with username and passwd
var validKafkaXWithAuthParams = map[string]string{
	"sasl":     "plaintext",
	"username": "admin",
	"password": "admin",
}

// A complete valid authParams example for sasl, without username and passwd
var validKafkaXWithoutAuthParams = map[string]string{}

var parseKafkaXMetadataTestDataset = []parseKafkaXMetadataTestData{
	// TODO: add test for empty topics string
	// failure, no consumer group
	{map[string]string{"bootstrapServers": "foobar:9092"}, true, 1, []string{"foobar:9092"}, "", nil, nil, "latest", false, false},
	// success, no topics
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group"}, false, 1, []string{"foobar:9092"}, "my-group", []string{}, nil, offsetResetPolicy("latest"), false, false},
	// success, ignore partitionLimitation if no topics
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "partitionLimitation": "1,2,3,4,5,6"}, false, 1, []string{"foobar:9092"}, "my-group", []string{}, nil, offsetResetPolicy("latest"), false, false},
	// success, no limitation with whitespaced limitation value
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "partitionLimitation": "           "}, false, 1, []string{"foobar:9092"}, "my-group", []string{}, nil, offsetResetPolicy("latest"), false, false},
	// success, no limitation
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "partitionLimitation": ""}, false, 1, []string{"foobar:9092"}, "my-group", []string{}, nil, offsetResetPolicy("latest"), false, false},
	// TODO: remove failure, version not supported??
	//{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "version": "1.2.3.4"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// failure, lagThreshold is negative value
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "lagThreshold": "-1"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// failure, lagThreshold is 0
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "lagThreshold": "0"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, activationLagThreshold is 0
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "lagThreshold": "10", "activationLagThreshold": "0"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, partitionLimitation as list
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "partitionLimitation": "1,2,3,4"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, []int32{1, 2, 3, 4}, offsetResetPolicy("latest"), false, false},
	// success, partitionLimitation as range
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "partitionLimitation": "1-4"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, []int32{1, 2, 3, 4}, offsetResetPolicy("latest"), false, false},
	// success, partitionLimitation mixed list + ranges
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "partitionLimitation": "1-4,8,10-12"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, []int32{1, 2, 3, 4, 8, 10, 11, 12}, offsetResetPolicy("latest"), false, false},
	// failure, partitionLimitation wrong data type
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "partitionLimitation": "a,b,c,d"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, more brokers
	{map[string]string{"bootstrapServers": "foo:9092,bar:9092", "consumerGroup": "my-group", "topic": "my-topics"}, false, 2, []string{"foo:9092", "bar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, offsetResetPolicy policy latest
	{map[string]string{"bootstrapServers": "foo:9092,bar:9092", "consumerGroup": "my-group", "topic": "my-topics", "offsetResetPolicy": "latest"}, false, 2, []string{"foo:9092", "bar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// failure, offsetResetPolicy policy wrong
	{map[string]string{"bootstrapServers": "foo:9092,bar:9092", "consumerGroup": "my-group", "topic": "my-topics", "offsetResetPolicy": "foo"}, true, 2, []string{"foo:9092", "bar:9092"}, "my-group", []string{"my-topics"}, nil, "", false, false},
	// success, offsetResetPolicy policy earliest
	{map[string]string{"bootstrapServers": "foo:9092,bar:9092", "consumerGroup": "my-group", "topic": "my-topics", "offsetResetPolicy": "earliest"}, false, 2, []string{"foo:9092", "bar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("earliest"), false, false},
	// failure, allowIdleConsumers malformed
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "notvalid"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, allowIdleConsumers is true
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), true, false},
	// failure, excludePersistentLag is malformed
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "excludePersistentLag": "notvalid"}, true, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, false},
	// success, excludePersistentLag is true
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "excludePersistentLag": "true"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), false, true},
	// success, version supported
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, false, 1, []string{"foobar:9092"}, "my-group", []string{"my-topics"}, nil, offsetResetPolicy("latest"), true, false},
}

var parseKafkaXAuthParamsTestDataset = []parseKafkaXAuthParamsTestData{
	// success, SASL only
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin"}, false, false},
	// success, SASL only
	{map[string]string{"sasl": "scram_sha256", "username": "admin", "password": "admin"}, false, false},
	// success, SASL only
	{map[string]string{"sasl": "scram_sha512", "username": "admin", "password": "admin"}, false, false},
	// success, TLS only
	{map[string]string{"tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, false, true},
	// success, TLS cert/key and assumed public CA
	{map[string]string{"tls": "enable", "cert": "ceert", "key": "keey"}, false, true},
	// success, TLS cert/key + key password and assumed public CA
	{map[string]string{"tls": "enable", "cert": "ceert", "key": "keey", "keyPassword": "keeyPassword"}, false, true},
	// success, TLS CA only
	{map[string]string{"tls": "enable", "ca": "caaa"}, false, true},
	// success, SASL + TLS
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, false, true},
	// success, SASL + TLS explicitly disabled
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "tls": "disable"}, false, false},
	// success, SASL OAUTHBEARER + TLS
	{map[string]string{"sasl": "oauthbearer", "username": "admin", "password": "admin", "scopes": "scope", "oauthTokenEndpointUri": "https://website.com", "tls": "disable"}, false, false},
	// failure, SASL OAUTHBEARER + TLS bad sasl type
	{map[string]string{"sasl": "foo", "username": "admin", "password": "admin", "scopes": "scope", "oauthTokenEndpointUri": "https://website.com", "tls": "disable"}, true, false},
	// success, SASL OAUTHBEARER + TLS missing scope
	{map[string]string{"sasl": "oauthbearer", "username": "admin", "password": "admin", "oauthTokenEndpointUri": "https://website.com", "tls": "disable"}, false, false},
	// failure, SASL OAUTHBEARER + TLS missing oauthTokenEndpointUri
	{map[string]string{"sasl": "oauthbearer", "username": "admin", "password": "admin", "scopes": "scope", "oauthTokenEndpointUri": "", "tls": "disable"}, true, false},
	// failure, SASL incorrect type
	{map[string]string{"sasl": "foo", "username": "admin", "password": "admin"}, true, false},
	// failure, SASL missing username
	{map[string]string{"sasl": "plaintext", "password": "admin"}, true, false},
	// failure, SASL missing password
	{map[string]string{"sasl": "plaintext", "username": "admin"}, true, false},
	// failure, TLS missing cert
	{map[string]string{"tls": "enable", "ca": "caaa", "key": "keey"}, true, false},
	// failure, TLS missing key
	{map[string]string{"tls": "enable", "ca": "caaa", "cert": "ceert"}, true, false},
	// failure, TLS invalid
	{map[string]string{"tls": "yes", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, incorrect sasl
	{map[string]string{"sasl": "foo", "username": "admin", "password": "admin", "tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, incorrect tls
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "tls": "foo", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing username
	{map[string]string{"sasl": "plaintext", "password": "admin", "tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing password
	{map[string]string{"sasl": "plaintext", "username": "admin", "tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing cert
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "tls": "enable", "ca": "caaa", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing key
	{map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "tls": "enable", "ca": "caaa", "cert": "ceert"}, true, false},
}
var parseKafkaXAuthParamsTestDataset2 = []parseKafkaXAuthParamsTestDataSecondAuthMethod{
	// success, SASL plaintext
	{map[string]string{"sasl": "plaintext", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin"}, false, false},
	// success, SASL scram_sha256
	{map[string]string{"sasl": "scram_sha256", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin"}, false, false},
	// success, SASL scram_sha512
	{map[string]string{"sasl": "scram_sha512", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin"}, false, false},
	// success, TLS only
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"ca": "caaa", "cert": "ceert", "key": "keey"}, false, true},
	// success, TLS cert/key and assumed public CA
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"cert": "ceert", "key": "keey"}, false, true},
	// success, TLS cert/key + key password and assumed public CA
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"cert": "ceert", "key": "keey", "keyPassword": "keeyPassword"}, false, true},
	// success, TLS CA only
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"ca": "caaa"}, false, true},
	// success, SASL + TLS
	{map[string]string{"sasl": "plaintext", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin", "ca": "caaa", "cert": "ceert", "key": "keey"}, false, true},
	// success, SASL + TLS explicitly disabled
	{map[string]string{"sasl": "plaintext", "tls": "disable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin"}, false, false},
	// failure, SASL incorrect type
	{map[string]string{"sasl": "foo", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin"}, true, false},
	// failure, SASL missing username
	{map[string]string{"sasl": "plaintext", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"password": "admin"}, true, false},
	// failure, SASL missing password
	{map[string]string{"sasl": "plaintext", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin"}, true, false},
	// failure, TLS missing cert
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"ca": "caaa", "key": "keey"}, true, false},
	// failure, TLS missing key
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"ca": "caaa", "cert": "ceert"}, true, false},
	// failure, TLS invalid
	{map[string]string{"tls": "random", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, incorrect SASL type
	{map[string]string{"sasl": "foo", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, incorrect tls
	{map[string]string{"sasl": "plaintext", "tls": "foo", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing username
	{map[string]string{"sasl": "plaintext", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"password": "admin", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing password
	{map[string]string{"sasl": "plaintext", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing cert
	{map[string]string{"sasl": "plaintext", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"username": "admin", "password": "admin", "ca": "caaa", "key": "keey"}, true, false},
	// failure, SASL + TLS, missing key
	{map[string]string{"sasl": "plaintext", "tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "plaintext", "username": "admin", "password": "admin", "ca": "caaa", "cert": "ceert"}, true, false},

	// failure, setting SASL values in both places
	{map[string]string{"sasl": "scram_sha512", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "scram_sha512", "username": "admin", "password": "admin"}, true, false},
	// failure, setting TLS values in both places
	{map[string]string{"tls": "enable", "bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"tls": "enable", "ca": "caaa", "cert": "ceert", "key": "keey"}, true, true},
	// success, setting SASL plaintext value with extra \n in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "plaintext\n", "username": "admin", "password": "admin"}, false, true},
	// success, setting SASL plaintext value with extra space in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "plaintext ", "username": "admin", "password": "admin"}, false, true},
	// success, setting SASL scram_sha256 value with extra \n in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "scram_sha256\n", "username": "admin", "password": "admin"}, false, true},
	// success, setting SASL scram_sha256 value with extra space in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "scram_sha256 ", "username": "admin", "password": "admin"}, false, true},
	// success, setting SASL scram_sha512 value with extra \n in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "scram_sha512\n", "username": "admin", "password": "admin"}, false, true},
	// success, setting SASL scram_sha512 value with extra space in TriggerAuthentication
	{map[string]string{"bootstrapServers": "foobar:9092", "consumerGroup": "my-group", "topic": "my-topics", "allowIdleConsumers": "true", "version": "1.0.0"}, map[string]string{"sasl": "scram_sha512 ", "username": "admin", "password": "admin"}, false, true},
}

var kafkaXMetricIdentifiers = []kafkaXMetricIdentifier{
	{&parseKafkaXMetadataTestDataset[10], 0, "s0-kafka-my-topics"},
	{&parseKafkaXMetadataTestDataset[10], 1, "s1-kafka-my-topics"},
	{&parseKafkaXMetadataTestDataset[2], 1, "s1-kafka-my-group-topics"},
}

func TestKafkaXGetBrokers(t *testing.T) {
	for _, testData := range parseKafkaXMetadataTestDataset {
		meta, err := parseKafkaMetadata(&ScalerConfig{TriggerMetadata: testData.metadata, AuthParams: validKafkaXWithAuthParams}, logr.Discard())

		if err != nil && !testData.isError {
			t.Error("Expected success but got error", err)
		}
		if testData.isError && err == nil {
			t.Error("Expected error but got success")
		}
		if len(meta.bootstrapServers) != testData.numBrokers {
			t.Errorf("Expected %d bootstrap servers but got %d\n", testData.numBrokers, len(meta.bootstrapServers))
		}
		if !reflect.DeepEqual(testData.brokers, meta.bootstrapServers) {
			t.Errorf("Expected %v but got %v\n", testData.brokers, meta.bootstrapServers)
		}
		if meta.group != testData.group {
			t.Errorf("Expected group %s but got %s\n", testData.group, meta.group)
		}
		if meta.topic != strings.Join(testData.topic, ",") {
			t.Errorf("Expected topics %v but got %v\n", testData.topic, meta.topic)
		}
		if !reflect.DeepEqual(testData.partitionLimitation, meta.partitionLimitation) {
			t.Errorf("Expected %v but got %v\n", testData.partitionLimitation, meta.partitionLimitation)
		}
		if err == nil && meta.offsetResetPolicy != testData.offsetResetPolicy {
			t.Errorf("Expected offsetResetPolicy %s but got %s\n", testData.offsetResetPolicy, meta.offsetResetPolicy)
		}

		meta, err = parseKafkaMetadata(&ScalerConfig{TriggerMetadata: testData.metadata, AuthParams: validKafkaXWithoutAuthParams}, logr.Discard())

		if err != nil && !testData.isError {
			t.Error("Expected success but got error", err)
		}
		if testData.isError && err == nil {
			t.Error("Expected error but got success")
		}
		if len(meta.bootstrapServers) != testData.numBrokers {
			t.Errorf("Expected %d bootstrap servers but got %d\n", testData.numBrokers, len(meta.bootstrapServers))
		}
		if !reflect.DeepEqual(testData.brokers, meta.bootstrapServers) {
			t.Errorf("Expected %v but got %v\n", testData.brokers, meta.bootstrapServers)
		}
		if meta.group != testData.group {
			t.Errorf("Expected group %s but got %s\n", testData.group, meta.group)
		}
		if meta.topic != strings.Join(testData.topic, ",") {
			t.Errorf("Expected topics %v but got %v\n", testData.topic, meta.topic)
		}
		if !reflect.DeepEqual(testData.partitionLimitation, meta.partitionLimitation) {
			t.Errorf("Expected %v but got %v\n", testData.partitionLimitation, meta.partitionLimitation)
		}
		if err == nil && meta.offsetResetPolicy != testData.offsetResetPolicy {
			t.Errorf("Expected offsetResetPolicy %s but got %s\n", testData.offsetResetPolicy, meta.offsetResetPolicy)
		}
		if err == nil && meta.allowIdleConsumers != testData.allowIdleConsumers {
			t.Errorf("Expected allowIdleConsumers %t but got %t\n", testData.allowIdleConsumers, meta.allowIdleConsumers)
		}
		if err == nil && meta.excludePersistentLag != testData.excludePersistentLag {
			t.Errorf("Expected excludePersistentLag %t but got %t\n", testData.excludePersistentLag, meta.excludePersistentLag)
		}
	}
}

func TestKafkaXAuthParams(t *testing.T) {
	// Testing tls and sasl value in TriggerAuthentication
	for _, testData := range parseKafkaXAuthParamsTestDataset {
		meta, err := parseKafkaMetadata(&ScalerConfig{TriggerMetadata: validKafkaXMetadata, AuthParams: testData.authParams}, logr.Discard())

		if err != nil && !testData.isError {
			t.Error("Expected success but got error", err)
		}
		if testData.isError && err == nil {
			t.Error("Expected error but got success")
		}
		if meta.enableTLS != testData.enableTLS {
			t.Errorf("Expected enableTLS to be set to %v but got %v\n", testData.enableTLS, meta.enableTLS)
		}
		if meta.enableTLS {
			if meta.ca != testData.authParams["ca"] {
				t.Errorf("Expected ca to be set to %v but got %v\n", testData.authParams["ca"], meta.enableTLS)
			}
			if meta.cert != testData.authParams["cert"] {
				t.Errorf("Expected cert to be set to %v but got %v\n", testData.authParams["cert"], meta.cert)
			}
			if meta.key != testData.authParams["key"] {
				t.Errorf("Expected key to be set to %v but got %v\n", testData.authParams["key"], meta.key)
			}
			if meta.keyPassword != testData.authParams["keyPassword"] {
				t.Errorf("Expected key to be set to %v but got %v\n", testData.authParams["keyPassword"], meta.key)
			}
		}
	}

	// Testing tls and sasl value in scaledObject
	for id, testData := range parseKafkaXAuthParamsTestDataset2 {
		meta, err := parseKafkaMetadata(&ScalerConfig{TriggerMetadata: testData.metadata, AuthParams: testData.authParams}, logr.Discard())

		if err != nil && !testData.isError {
			t.Errorf("Test case: %v. Expected success but got error %v", id, err)
		}
		if testData.isError && err == nil {
			t.Errorf("Test case: %v. Expected error but got success", id)
		}
		if !testData.isError {
			if testData.metadata["tls"] == "true" && !meta.enableTLS {
				t.Errorf("Test case: %v. Expected tls to be set to %v but got %v\n", id, testData.metadata["tls"], meta.enableTLS)
			}
			if meta.enableTLS {
				if meta.ca != testData.authParams["ca"] {
					t.Errorf("Test case: %v. Expected ca to be set to %v but got %v\n", id, testData.authParams["ca"], meta.ca)
				}
				if meta.cert != testData.authParams["cert"] {
					t.Errorf("Test case: %v. Expected cert to be set to %v but got %v\n", id, testData.authParams["cert"], meta.cert)
				}
				if meta.key != testData.authParams["key"] {
					t.Errorf("Test case: %v. Expected key to be set to %v but got %v\n", id, testData.authParams["key"], meta.key)
				}
				if meta.keyPassword != testData.authParams["keyPassword"] {
					t.Errorf("Test case: %v. Expected key to be set to %v but got %v\n", id, testData.authParams["keyPassword"], meta.keyPassword)
				}
			}
		}
	}
}

func TestKafkaXGetMetricSpecForScaling(t *testing.T) {
	for _, testData := range kafkaXMetricIdentifiers {
		meta, err := parseKafkaXMetadata(&ScalerConfig{TriggerMetadata: testData.metadataTestData.metadata, AuthParams: validKafkaXWithAuthParams, ScalerIndex: testData.scalerIndex}, logr.Discard())
		if err != nil {
			t.Fatal("Could not parse metadata:", err)
		}
		mockKafkaScaler := kafkaXScaler{"", meta, nil, nil, logr.Discard(), make(map[string]map[int]int64)}

		metricSpec := mockKafkaScaler.GetMetricSpecForScaling(context.Background())
		metricName := metricSpec[0].External.Metric.Name
		if metricName != testData.name {
			str := fmt.Sprintf("Wrong External metric source name: %s, expected: %s for %v\n", metricName, testData.name, testData)
			t.Error("Wrong External metric source name:", metricName, str)
		}
	}
}

