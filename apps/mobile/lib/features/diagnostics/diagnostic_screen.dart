import 'package:flutter/material.dart';
import '../../core/execution/action_gateway.dart';
import '../../core/execution/consent_token.dart';
import '../../core/fusion/evaluation_result.dart';
import '../../core/payload/parsed_payload.dart';
import '../../core/payload/qr_payload.dart';

/// Diagnostic screen displaying explainable evidence, risk warnings,
/// and gated ActionGateway consent controls.
class DiagnosticScreen extends StatefulWidget {
  final QRPayload qrPayload;
  final ParsedPayload parsedPayload;
  final EvaluationResult evaluation;
  final ActionGateway actionGateway;
  final VoidCallback? onDismiss;

  const DiagnosticScreen({
    super.key,
    required this.qrPayload,
    required this.parsedPayload,
    required this.evaluation,
    required this.actionGateway,
    this.onDismiss,
  });

  @override
  State<DiagnosticScreen> createState() => _DiagnosticScreenState();
}

class _DiagnosticScreenState extends State<DiagnosticScreen> {
  late ConsentToken _consentToken;
  bool _unknownConsentChecked = false;
  ActionExecutionResult? _executionResult;
  bool _isExecuting = false;

  @override
  void initState() {
    super.initState();
    _consentToken = widget.actionGateway.createToken(
      scanId: widget.qrPayload.scanId,
      actionType: _mapActionType(widget.parsedPayload.type),
      canonicalTarget: widget.parsedPayload.rawInput,
    );
  }

  DestinationActionType _mapActionType(PayloadType type) {
    switch (type) {
      case PayloadType.url:
        return DestinationActionType.viewUrl;
      case PayloadType.upi:
        return DestinationActionType.initiatePayment;
      case PayloadType.phone:
        return DestinationActionType.dialPhone;
      case PayloadType.wifi:
        return DestinationActionType.displayWifi;
      case PayloadType.text:
        return DestinationActionType.copyText;
    }
  }

  Color _getStateColor(EvaluationState state) {
    switch (state) {
      case EvaluationState.verified:
        return Colors.green.shade700;
      case EvaluationState.unknown:
        return Colors.orange.shade800;
      case EvaluationState.suspicious:
        return Colors.red.shade700;
    }
  }

  IconData _getStateIcon(EvaluationState state) {
    switch (state) {
      case EvaluationState.verified:
        return Icons.verified;
      case EvaluationState.unknown:
        return Icons.help_outline;
      case EvaluationState.suspicious:
        return Icons.warning_amber_rounded;
    }
  }

  Future<void> _handleProceed() async {
    setState(() {
      _isExecuting = true;
    });

    final res = await widget.actionGateway.executeAction(
      evaluation: widget.evaluation,
      token: _consentToken,
      userConfirmedUnknown: _unknownConsentChecked,
    );

    setState(() {
      _executionResult = res;
      _isExecuting = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = widget.evaluation.state;
    final stateColor = _getStateColor(state);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Diagnostics'),
        backgroundColor: Colors.indigo,
        foregroundColor: Colors.white,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Evaluation State Banner
            Card(
              elevation: 3,
              color: stateColor.withAlpha(25),
              shape: RoundedRectangleBorder(
                side: BorderSide(color: stateColor, width: 2),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Row(
                  children: [
                    Icon(_getStateIcon(state), size: 48, color: stateColor),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'VERDICT: ${state.name.toUpperCase()}',
                            key: const Key('verdict_state_text'),
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                              color: stateColor,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            'Category: ${widget.parsedPayload.type.name.toUpperCase()}',
                            style: const TextStyle(fontWeight: FontWeight.w500),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Masked Target Value Card
            Card(
              elevation: 1,
              child: Padding(
                padding: const EdgeInsets.all(14.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Target (Redacted/Masked):',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 6),
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.grey.shade100,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: SelectableText(
                        widget.qrPayload.maskedPreview,
                        key: const Key('diagnostic_target_preview'),
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 13,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Degradation / Component Status
            Card(
              elevation: 1,
              child: Padding(
                padding: const EdgeInsets.all(12.0),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _buildStatusChip(
                      'KB',
                      widget.evaluation.degradationFlags['kbAvailable'] ??
                          false,
                    ),
                    _buildStatusChip(
                      'ML (M8)',
                      widget.evaluation.degradationFlags['mlAvailable'] ??
                          false,
                    ),
                    _buildStatusChip(
                      'Network',
                      widget.evaluation.degradationFlags['networkAvailable'] ??
                          false,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Evidence and Reasons
            const Text(
              'Explainable Evidence & Reasons:',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
            ),
            const SizedBox(height: 8),
            ...widget.evaluation.userMessages.map(
              (msg) => Card(
                elevation: 1,
                margin: const EdgeInsets.only(bottom: 6),
                child: ListTile(
                  dense: true,
                  leading: const Icon(Icons.info_outline, color: Colors.indigo),
                  title: Text(msg),
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Warning Banner for Unknown or Suspicious
            if (state == EvaluationState.suspicious) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.red.shade100,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.red.shade400),
                ),
                child: Row(
                  children: const [
                    Icon(Icons.block, color: Colors.red),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'This payload is SUSPICIOUS and has been blocked to protect your device. No action can be launched.',
                        style: TextStyle(
                          color: Colors.red,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ] else if (state == EvaluationState.unknown) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.orange.shade300),
                ),
                child: Column(
                  children: [
                    Row(
                      children: const [
                        Icon(Icons.warning, color: Colors.orange),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Notice: Target identity cannot be positively verified. Proceed only if you trust the physical source.',
                            style: TextStyle(fontWeight: FontWeight.w600),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    CheckboxListTile(
                      key: const Key('unknown_consent_checkbox'),
                      value: _unknownConsentChecked,
                      onChanged: (val) {
                        setState(() {
                          _unknownConsentChecked = val ?? false;
                        });
                      },
                      dense: true,
                      title: const Text(
                        'I understand the risks and explicitly wish to proceed',
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 20),

            // Execution Status Feedback
            if (_executionResult != null) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: _executionResult!.success
                      ? Colors.green.shade50
                      : Colors.red.shade50,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  _executionResult!.message,
                  key: const Key('execution_result_message'),
                  style: TextStyle(
                    color: _executionResult!.success
                        ? Colors.green.shade800
                        : Colors.red.shade800,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // Action Gateway Controls
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    key: const Key('diagnostic_cancel_button'),
                    onPressed: () {
                      if (widget.onDismiss != null) {
                        widget.onDismiss!();
                      } else {
                        Navigator.of(context).pop();
                      }
                    },
                    child: const Text('Cancel / Dismiss'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton(
                    key: const Key('diagnostic_proceed_button'),
                    onPressed:
                        (state == EvaluationState.suspicious || _isExecuting)
                        ? null
                        : _handleProceed,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.indigo,
                      foregroundColor: Colors.white,
                    ),
                    child: _isExecuting
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                              color: Colors.white,
                              strokeWidth: 2,
                            ),
                          )
                        : const Text('Proceed to Action'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusChip(String label, bool isAvailable) {
    return Chip(
      avatar: Icon(
        isAvailable ? Icons.check_circle : Icons.cancel_outlined,
        color: isAvailable ? Colors.green : Colors.grey,
        size: 16,
      ),
      label: Text(
        '$label: ${isAvailable ? 'OK' : 'OFF'}',
        style: const TextStyle(fontSize: 12),
      ),
    );
  }
}
