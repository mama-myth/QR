/// Supported primary QR payload categories.
enum PayloadType { url, upi, phone, wifi, text }

/// Base abstract class for all typed, parsed QR payloads.
///
/// Invariants:
/// - Parsing is deterministic, side-effect-free, and bounded.
/// - No external action, navigation, payment, dialing, or connection is triggered.
abstract class ParsedPayload {
  final PayloadType type;
  final String rawInput;
  final bool isMalformed;
  final String? parseError;

  const ParsedPayload({
    required this.type,
    required this.rawInput,
    this.isMalformed = false,
    this.parseError,
  });

  /// Map of redacted diagnostic properties suitable for logging or report display.
  Map<String, dynamic> get diagnosticProperties;
}

/// Parsed representation of a URL payload.
class UrlPayload extends ParsedPayload {
  final String? scheme;
  final String? host;
  final int? port;
  final String path;
  final Map<String, String> queryParameters;
  final List<String> duplicateParameters;
  final String? userInfo;
  final bool hasEmbeddedCredentials;
  final bool hasUnicodeConfusables;

  const UrlPayload({
    required super.rawInput,
    super.isMalformed = false,
    super.parseError,
    this.scheme,
    this.host,
    this.port,
    this.path = '',
    this.queryParameters = const {},
    this.duplicateParameters = const [],
    this.userInfo,
    this.hasEmbeddedCredentials = false,
    this.hasUnicodeConfusables = false,
  }) : super(type: PayloadType.url);

  @override
  Map<String, dynamic> get diagnosticProperties => {
    'type': 'URL',
    'scheme': scheme ?? '<none>',
    'host': host ?? '<none>',
    'port': port,
    'path': path,
    'hasUserInfo': hasEmbeddedCredentials,
    'duplicateParams': duplicateParameters,
    'isMalformed': isMalformed,
    if (parseError != null) 'parseError': parseError,
  };
}

/// Parsed representation of a UPI payment payload (`upi://pay`).
class UpiPayload extends ParsedPayload {
  final String? payeeVpa; // 'pa'
  final String? payeeName; // 'pn'
  final String? amount; // 'am'
  final String? currency; // 'cu'
  final String? note; // 'tn'
  final String? merchantCode; // 'mc'
  final String? transactionRef; // 'tr'
  final List<String> duplicateParameters;
  final Map<String, String> allParameters;

  const UpiPayload({
    required super.rawInput,
    super.isMalformed = false,
    super.parseError,
    this.payeeVpa,
    this.payeeName,
    this.amount,
    this.currency,
    this.note,
    this.merchantCode,
    this.transactionRef,
    this.duplicateParameters = const [],
    this.allParameters = const {},
  }) : super(type: PayloadType.upi);

  @override
  Map<String, dynamic> get diagnosticProperties => {
    'type': 'UPI',
    'payeeVpa': payeeVpa != null ? _maskVpa(payeeVpa!) : '<missing>',
    'payeeName': payeeName ?? '<none>',
    'amount': amount ?? '<unspecified>',
    'currency': currency ?? 'INR',
    'duplicateParams': duplicateParameters,
    'isMalformed': isMalformed,
    if (parseError != null) 'parseError': parseError,
  };

  static String _maskVpa(String vpa) {
    final parts = vpa.split('@');
    if (parts.length != 2) return '***';
    final user = parts[0];
    final handle = parts[1];
    if (user.length <= 2) return '${user[0]}*@$handle';
    return '${user.substring(0, 2)}***@$handle';
  }
}

/// Parsed representation of a Phone payload (`tel:`).
class PhonePayload extends ParsedPayload {
  final String sanitizedNumber;
  final bool containsControlChars;

  const PhonePayload({
    required super.rawInput,
    super.isMalformed = false,
    super.parseError,
    required this.sanitizedNumber,
    this.containsControlChars = false,
  }) : super(type: PayloadType.phone);

  @override
  Map<String, dynamic> get diagnosticProperties => {
    'type': 'PHONE',
    'sanitizedNumber': _maskPhone(sanitizedNumber),
    'containsControlChars': containsControlChars,
    'isMalformed': isMalformed,
    if (parseError != null) 'parseError': parseError,
  };

  static String _maskPhone(String num) {
    if (num.length <= 4) return '***';
    return '${num.substring(0, num.length - 4)}****';
  }
}

/// Parsed representation of a Wi-Fi QR payload (`WIFI:...`).
class WifiPayload extends ParsedPayload {
  final String? ssid;
  final String authType; // 'WPA', 'WEP', 'nopass', etc.
  final bool isHidden;
  final bool hasPassword;

  const WifiPayload({
    required super.rawInput,
    super.isMalformed = false,
    super.parseError,
    this.ssid,
    this.authType = 'nopass',
    this.isHidden = false,
    this.hasPassword = false,
  }) : super(type: PayloadType.wifi);

  @override
  Map<String, dynamic> get diagnosticProperties => {
    'type': 'WIFI',
    'ssid': ssid ?? '<unknown>',
    'authType': authType,
    'isHidden': isHidden,
    'hasPassword': hasPassword,
    'isMalformed': isMalformed,
    if (parseError != null) 'parseError': parseError,
  };
}

/// Parsed representation of an arbitrary text or fallback payload.
class TextPayload extends ParsedPayload {
  final int characterCount;
  final bool containsControlChars;

  const TextPayload({
    required super.rawInput,
    super.isMalformed = false,
    super.parseError,
    required this.characterCount,
    this.containsControlChars = false,
  }) : super(type: PayloadType.text);

  @override
  Map<String, dynamic> get diagnosticProperties => {
    'type': 'TEXT',
    'characterCount': characterCount,
    'containsControlChars': containsControlChars,
    'isMalformed': isMalformed,
    if (parseError != null) 'parseError': parseError,
  };
}
