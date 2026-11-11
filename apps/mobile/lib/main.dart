import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'features/scanner/scanner_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PeekInQRApp());
}

class PeekInQRApp extends StatefulWidget {
  const PeekInQRApp({super.key});

  @override
  State<PeekInQRApp> createState() => _PeekInQRAppState();
}

class _PeekInQRAppState extends State<PeekInQRApp> {
  static const platform = MethodChannel('org.peekinqr.peek_in_qr/platform');
  String _entrypoint = 'app_icon';

  @override
  void initState() {
    super.initState();
    _fetchLaunchEntrypoint();
  }

  Future<void> _fetchLaunchEntrypoint() async {
    try {
      final String? result = await platform.invokeMethod<String>('getLaunchEntrypoint');
      if (result != null && mounted) {
        setState(() {
          _entrypoint = result;
        });
      }
    } catch (_) {
      // MethodChannel unavailable (e.g. running outside Android/test environment)
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Peek-in QR',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: ScannerScreen(initialEntrypoint: _entrypoint),
      debugShowCheckedModeBanner: false,
    );
  }
}
