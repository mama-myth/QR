import 'package:flutter_test/flutter_test.dart';
import 'package:peek_in_qr/core/fusion/evaluation_result.dart';
import 'package:peek_in_qr/core/fusion/fusion_engine.dart';
import 'package:peek_in_qr/core/ml/feature_extractor.dart';
import 'package:peek_in_qr/core/ml/model_adapter.dart';
import 'package:peek_in_qr/core/payload/payload_parser.dart';

void main() {
  group('FeatureExtractor Vectors', () {
    test('extracts lexical and statistical features for URLs', () {
      final payload = PayloadParser.parse(
        'https://example.com/login?token=abc',
      );
      final vector = FeatureExtractor.extract(payload);

      expect(vector.features.containsKey('raw_length'), isTrue);
      expect(vector.features['raw_length'], greaterThan(0));
      expect(vector.features.containsKey('entropy'), isTrue);
      expect(vector.features['entropy'], greaterThan(0));
      expect(vector.features['host_length'], equals(11.0)); // 'example.com'
      expect(vector.features['subdomain_count'], equals(2.0));
      expect(vector.features['query_param_count'], equals(1.0));
      expect(vector.features['has_userinfo'], equals(0.0));
    });

    test('extracts features for UPI payloads', () {
      final payload = PayloadParser.parse('upi://pay?pa=store@icici&am=100.00');
      final vector = FeatureExtractor.extract(payload);

      expect(vector.features['has_amount'], equals(1.0));
      expect(vector.features['vpa_length'], equals(11.0)); // 'store@icici'
    });

    test('extracts features for Wi-Fi payloads', () {
      final payload = PayloadParser.parse('WIFI:S:PublicCafe;T:nopass;;');
      final vector = FeatureExtractor.extract(payload);

      expect(vector.features['is_open'], equals(1.0));
      expect(vector.features['ssid_length'], equals(10.0)); // 'PublicCafe'
    });
  });

  group('MlModelAdapter and Fusion Fallback', () {
    test(
      'DefaultMlModelAdapter reports unavailable without throwing or fabricating scores',
      () async {
        final adapter = DefaultMlModelAdapter();
        expect(adapter.isModelLoaded, isFalse);
        expect(adapter.metadata, isNull);

        final dummyVector = const FeatureVector({'raw_length': 20.0});
        final result = await adapter.predict(dummyVector);

        expect(result.status, MlInferenceStatus.unavailable);
        expect(result.confidence, isNull);
        expect(result.predictedLabel, isNull);
        expect(
          result.diagnosticReason.contains(
            'No licensed, provenance-validated on-device ML model artifact is installed',
          ),
          isTrue,
        );
      },
    );

    test('FusionEngine reflects mlAvailable degradation flag accurately', () {
      final adapter = DefaultMlModelAdapter();
      final engine = FusionEngine(mlAdapter: adapter);

      final payload = PayloadParser.parse('https://example.com');
      final eval = engine.evaluate(payload);

      expect(eval.degradationFlags['mlAvailable'], isFalse);
      expect(eval.state, EvaluationState.unknown);
    });
  });
}
