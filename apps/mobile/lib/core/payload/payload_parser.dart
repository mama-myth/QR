import 'parsed_payload.dart';

/// Bounded, deterministic QR payload parser factory and dispatcher.
///
/// Security Invariants:
/// - Resource bounded: maximum input length check (default 8192 bytes)
/// - Lossless preservation of raw input for security analysis
/// - No external resolution, DNS lookup, or intent execution
class PayloadParser {
  static const int maxInputLength = 8192;

  /// Parses an arbitrary raw QR string into a strongly-typed `ParsedPayload`.
  static ParsedPayload parse(String raw) {
    if (raw.length > maxInputLength) {
      return TextPayload(
        rawInput: raw.substring(0, maxInputLength),
        isMalformed: true,
        parseError: 'Payload exceeds maximum bounded length ($maxInputLength characters)',
        characterCount: raw.length,
      );
    }

    final trimmed = raw.trim();

    // 1. Check for UPI URI scheme
    if (trimmed.toLowerCase().startsWith('upi://pay')) {
      return _parseUpi(trimmed);
    }

    // 2. Check for Phone URI scheme
    if (trimmed.toLowerCase().startsWith('tel:')) {
      return _parsePhone(trimmed);
    }

    // 3. Check for Wi-Fi format
    if (trimmed.toUpperCase().startsWith('WIFI:')) {
      return _parseWifi(trimmed);
    }

    // 4. Check for Web URL schemes
    if (trimmed.toLowerCase().startsWith('http://') ||
        trimmed.toLowerCase().startsWith('https://')) {
      return _parseUrl(trimmed);
    }

    // 5. Fallback: Arbitrary Text
    return _parseText(raw);
  }

  static UrlPayload _parseUrl(String input) {
    try {
      final uri = Uri.parse(input);
      if (uri.scheme.isEmpty || (uri.scheme != 'http' && uri.scheme != 'https')) {
        return UrlPayload(
          rawInput: input,
          isMalformed: true,
          parseError: 'Unsupported or missing URL scheme: ${uri.scheme}',
        );
      }

      // Detect duplicate query parameters
      final queryPairs = uri.query.isNotEmpty ? uri.query.split('&') : <String>[];
      final seenParams = <String>{};
      final duplicates = <String>[];
      for (final pair in queryPairs) {
        if (pair.isEmpty) continue;
        final eqIdx = pair.indexOf('=');
        final key = eqIdx != -1 ? pair.substring(0, eqIdx) : pair;
        final decodedKey = Uri.decodeQueryComponent(key);
        if (seenParams.contains(decodedKey)) {
          if (!duplicates.contains(decodedKey)) {
            duplicates.add(decodedKey);
          }
        } else {
          seenParams.add(decodedKey);
        }
      }

      // Check for userinfo / embedded credentials
      final hasUserInfo = uri.userInfo.isNotEmpty;

      // Check for Unicode confusables or non-ASCII characters in host
      final host = uri.host;
      final hasConfusables = host.codeUnits.any((c) => c > 127) || host.toLowerCase().contains('xn--');

      return UrlPayload(
        rawInput: input,
        scheme: uri.scheme,
        host: uri.host,
        port: uri.hasPort ? uri.port : null,
        path: uri.path,
        queryParameters: uri.queryParameters,
        duplicateParameters: duplicates,
        userInfo: uri.userInfo.isNotEmpty ? uri.userInfo : null,
        hasEmbeddedCredentials: hasUserInfo,
        hasUnicodeConfusables: hasConfusables,
      );
    } catch (e) {
      return UrlPayload(
        rawInput: input,
        isMalformed: true,
        parseError: 'URI parse error: $e',
      );
    }
  }

  static UpiPayload _parseUpi(String input) {
    try {
      final uri = Uri.parse(input);
      final queryPairs = uri.query.isNotEmpty ? uri.query.split('&') : <String>[];
      final seenParams = <String>{};
      final duplicates = <String>[];
      final allParams = <String, String>{};

      for (final pair in queryPairs) {
        if (pair.isEmpty) continue;
        final eqIdx = pair.indexOf('=');
        final rawKey = eqIdx != -1 ? pair.substring(0, eqIdx) : pair;
        final rawVal = eqIdx != -1 ? pair.substring(eqIdx + 1) : '';
        final key = Uri.decodeQueryComponent(rawKey);
        final val = Uri.decodeQueryComponent(rawVal);

        if (seenParams.contains(key)) {
          if (!duplicates.contains(key)) {
            duplicates.add(key);
          }
        } else {
          seenParams.add(key);
          allParams[key] = val;
        }
      }

      final payeeVpa = allParams['pa'];
      final payeeName = allParams['pn'];
      final amount = allParams['am'];
      final currency = allParams['cu'];
      final note = allParams['tn'];
      final merchantCode = allParams['mc'];
      final transactionRef = allParams['tr'];

      final isMalformed = payeeVpa == null || payeeVpa.trim().isEmpty;

      return UpiPayload(
        rawInput: input,
        isMalformed: isMalformed,
        parseError: isMalformed ? 'Missing mandatory UPI payee VPA (pa)' : null,
        payeeVpa: payeeVpa,
        payeeName: payeeName,
        amount: amount,
        currency: currency,
        note: note,
        merchantCode: merchantCode,
        transactionRef: transactionRef,
        duplicateParameters: duplicates,
        allParameters: allParams,
      );
    } catch (e) {
      return UpiPayload(
        rawInput: input,
        isMalformed: true,
        parseError: 'Malformed UPI URI: $e',
      );
    }
  }

  static PhonePayload _parsePhone(String input) {
    try {
      final rawNumber = input.substring(4); // strip 'tel:'
      final containsControl = rawNumber.codeUnits.any((c) => c < 32 || c == 127);
      // Sanitize: allow digits, +, *, #
      final sanitized = rawNumber.replaceAll(RegExp(r'[^0-9+*#]'), '');

      final isMalformed = sanitized.isEmpty;

      return PhonePayload(
        rawInput: input,
        sanitizedNumber: sanitized,
        containsControlChars: containsControl,
        isMalformed: isMalformed,
        parseError: isMalformed ? 'Empty or invalid phone number in tel URI' : null,
      );
    } catch (e) {
      return PhonePayload(
        rawInput: input,
        sanitizedNumber: '',
        isMalformed: true,
        parseError: 'Malformed tel URI: $e',
      );
    }
  }

  static WifiPayload _parseWifi(String input) {
    // Syntax: WIFI:S:<ssid>;T:<auth>;P:<password>;H:<hidden>;;
    final body = input.substring(5); // strip WIFI:
    final fields = <String, String>{};

    var current = StringBuffer();
    var isEscaped = false;
    final tokens = <String>[];

    for (var i = 0; i < body.length; i++) {
      final char = body[i];
      if (isEscaped) {
        current.write(char);
        isEscaped = false;
      } else if (char == '\\') {
        isEscaped = true;
      } else if (char == ';') {
        tokens.add(current.toString());
        current = StringBuffer();
      } else {
        current.write(char);
      }
    }
    if (current.isNotEmpty) {
      tokens.add(current.toString());
    }

    for (final token in tokens) {
      if (token.isEmpty) continue;
      final colonIdx = token.indexOf(':');
      if (colonIdx != -1) {
        final key = token.substring(0, colonIdx);
        final val = token.substring(colonIdx + 1);
        fields[key] = val;
      }
    }

    final ssid = fields['S'];
    final auth = fields['T'] ?? 'nopass';
    final password = fields['P'];
    final hidden = fields['H'] == 'true' || fields['H'] == '1';

    final isMalformed = ssid == null || ssid.isEmpty;

    return WifiPayload(
      rawInput: input,
      ssid: ssid,
      authType: auth,
      isHidden: hidden,
      hasPassword: password != null && password.isNotEmpty,
      isMalformed: isMalformed,
      parseError: isMalformed ? 'Missing mandatory SSID in Wi-Fi payload' : null,
    );
  }

  static TextPayload _parseText(String input) {
    final hasControl = input.codeUnits.any((c) => (c < 32 && c != 9 && c != 10 && c != 13) || c == 127);
    return TextPayload(
      rawInput: input,
      characterCount: input.length,
      containsControlChars: hasControl,
    );
  }
}
