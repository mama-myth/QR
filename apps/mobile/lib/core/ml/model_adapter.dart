import 'feature_extractor.dart';

/// Status of on-device ML inference capability.
enum MlInferenceStatus {
  available,
  unavailable,
  error,
}

/// Metadata contract for on-device machine learning models.
class ModelMetadata {
  final String modelName;
  final String version;
  final String sha256Checksum;
  final String datasetProvenance;
  final double calibrationThreshold;

  const ModelMetadata({
    required this.modelName,
    required this.version,
    required this.sha256Checksum,
    required this.datasetProvenance,
    required this.calibrationThreshold,
  });
}

/// Result produced by on-device ML evaluation.
class MlInferenceResult {
  final MlInferenceStatus status;
  final double? confidence;
  final String? predictedLabel; // e.g. 'ANOMALY', 'BENIGN'
  final String diagnosticReason;

  const MlInferenceResult({
    required this.status,
    this.confidence,
    this.predictedLabel,
    required this.diagnosticReason,
  });

  bool get isAvailable => status == MlInferenceStatus.available;
}

/// On-device ML Model Adapter.
///
/// Invariants:
/// - Never fake inference or generate random probability scores.
/// - If no authenticated, licensed model artifact is installed, reports `unavailable`.
/// - Missing or unavailable ML never increases assurance or alters deterministic rules.
abstract class MlModelAdapter {
  bool get isModelLoaded;
  ModelMetadata? get metadata;
  Future<MlInferenceResult> predict(FeatureVector features);
}

/// Default implementation when no licensed, verified on-device model artifact is present.
class DefaultMlModelAdapter implements MlModelAdapter {
  @override
  bool get isModelLoaded => false;

  @override
  ModelMetadata? get metadata => null;

  @override
  Future<MlInferenceResult> predict(FeatureVector features) async {
    return const MlInferenceResult(
      status: MlInferenceStatus.unavailable,
      confidence: null,
      predictedLabel: null,
      diagnosticReason: 'No licensed, provenance-validated on-device ML model artifact is installed. Preserving safe deterministic evaluation.',
    );
  }
}
