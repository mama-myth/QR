import 'dart:math';
import '../payload/parsed_payload.dart';

/// Extracted numerical and categorical feature vector for on-device ML evaluation.
class FeatureVector {
  final Map<String, double> features;

  const FeatureVector(this.features);

  List<double> toList() => features.values.toList();
}

/// Deterministic local feature extractor for QR payloads.
class FeatureExtractor {
  /// Extracts lightweight statistical and lexical features from a parsed payload.
  static FeatureVector extract(ParsedPayload payload) {
    final map = <String, double>{};

    final raw = payload.rawInput;
    map['raw_length'] = raw.length.toDouble();
    map['entropy'] = _computeEntropy(raw);
    map['digit_ratio'] = _computeDigitRatio(raw);
    map['symbol_ratio'] = _computeSymbolRatio(raw);

    if (payload is UrlPayload) {
      final host = payload.host ?? '';
      map['host_length'] = host.length.toDouble();
      map['host_entropy'] = _computeEntropy(host);
      map['subdomain_count'] = host.split('.').length.toDouble();
      map['path_length'] = payload.path.length.toDouble();
      map['query_param_count'] = payload.queryParameters.length.toDouble();
      map['has_userinfo'] = payload.hasEmbeddedCredentials ? 1.0 : 0.0;
      map['has_confusable'] = payload.hasUnicodeConfusables ? 1.0 : 0.0;
      map['has_duplicate_params'] = payload.duplicateParameters.isNotEmpty ? 1.0 : 0.0;
    } else if (payload is UpiPayload) {
      map['vpa_length'] = (payload.payeeVpa ?? '').length.toDouble();
      map['has_amount'] = payload.amount != null ? 1.0 : 0.0;
      map['duplicate_params'] = payload.duplicateParameters.isNotEmpty ? 1.0 : 0.0;
    } else if (payload is WifiPayload) {
      map['ssid_length'] = (payload.ssid ?? '').length.toDouble();
      map['is_open'] = payload.authType.toUpperCase() == 'NOPASS' ? 1.0 : 0.0;
      map['is_hidden'] = payload.isHidden ? 1.0 : 0.0;
    } else if (payload is PhonePayload) {
      map['phone_length'] = payload.sanitizedNumber.length.toDouble();
      map['has_control_chars'] = payload.containsControlChars ? 1.0 : 0.0;
    } else if (payload is TextPayload) {
      map['char_count'] = payload.characterCount.toDouble();
      map['has_control_chars'] = payload.containsControlChars ? 1.0 : 0.0;
    }

    return FeatureVector(map);
  }

  static double _computeEntropy(String input) {
    if (input.isEmpty) return 0.0;
    final frequencies = <int, int>{};
    for (final unit in input.codeUnits) {
      frequencies[unit] = (frequencies[unit] ?? 0) + 1;
    }
    final len = input.length.toDouble();
    var entropy = 0.0;
    for (final count in frequencies.values) {
      final p = count / len;
      entropy -= p * (log(p) / ln2);
    }
    return entropy;
  }

  static double _computeDigitRatio(String input) {
    if (input.isEmpty) return 0.0;
    final digits = input.codeUnits.where((c) => c >= 48 && c <= 57).length;
    return digits / input.length;
  }

  static double _computeSymbolRatio(String input) {
    if (input.isEmpty) return 0.0;
    final symbols = input.codeUnits.where((c) {
      final isAlpha = (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
      final isDigit = c >= 48 && c <= 57;
      return !isAlpha && !isDigit;
    }).length;
    return symbols / input.length;
  }
}
