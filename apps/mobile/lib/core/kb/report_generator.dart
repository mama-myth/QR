import '../fusion/evaluation_result.dart';
import '../payload/parsed_payload.dart';
import '../payload/qr_payload.dart';
import 'kb_models.dart';

/// Diagnostic audit report generator.
///
/// Invariants:
/// - Never includes raw QR payloads, full URL query strings, or Wi-Fi passwords by default.
/// - Exports machine-readable and auditable diagnostics containing scan ID,
///   entrypoint, timestamp, masked target summary, evaluation verdict, and reasons.
class DiagnosticReportGenerator {
  /// Generates a redacted diagnostic report map suitable for export or auditing.
  static Map<String, dynamic> generateReport({
    required QRPayload qrPayload,
    required ParsedPayload parsedPayload,
    required EvaluationResult evaluation,
    String consentAction = 'PENDING',
  }) {
    return {
      'reportVersion': '1.0.0',
      'scanMetadata': {
        'scanId': qrPayload.scanId,
        'entrypoint': qrPayload.entrypoint,
        'timestamp': qrPayload.timestamp.toIso8601String(),
        'payloadType': parsedPayload.type.name.toUpperCase(),
      },
      'targetSummary': {
        'maskedPreview': qrPayload.maskedPreview,
        'diagnosticProperties': parsedPayload.diagnosticProperties,
      },
      'evaluationVerdict': {
        'state': evaluation.state.name.toUpperCase(),
        'reasonCodes': evaluation.reasonCodes,
        'userMessages': evaluation.userMessages,
        'evaluatedOnline': evaluation.evaluatedOnline,
        'degradationFlags': evaluation.degradationFlags,
        'policyVersion': evaluation.policyVersion,
        'evidence': evaluation.evidenceList.map((e) => e.toJson()).toList(),
      },
      'actionAudit': {
        'consentAction': consentAction,
        'generatedAt': DateTime.now().toUtc().toIso8601String(),
      },
    };
  }

  /// Converts a ScanRecord into an exported historical summary map.
  static Map<String, dynamic> generateHistoricalSummary(ScanRecord record) {
    return {
      'scanId': record.scanId,
      'timestamp': record.timestamp.toIso8601String(),
      'type': record.payloadType,
      'state': record.evaluationState,
      'consentAction': record.consentAction,
      'redactedSummary': record.redactedSummary,
      'reasons': record.reasonCodes,
    };
  }
}
