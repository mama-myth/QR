import '../fusion/evaluation_result.dart';
import 'consent_token.dart';

/// Execution outcome returned by the ActionGateway.
class ActionExecutionResult {
  final bool success;
  final String
  status; // 'EXECUTED', 'BLOCKED', 'CANCELLED', 'STALE_TOKEN', 'ERROR'
  final String message;

  const ActionExecutionResult({
    required this.success,
    required this.status,
    required this.message,
  });
}

/// Abstract handler interface for invoking platform-level external intents.
abstract class PlatformActionDispatcher {
  Future<bool> launchIntent(DestinationActionType type, String target);
}

/// Default mock/in-memory dispatcher for headless testing and safe execution.
class SafeActionDispatcher implements PlatformActionDispatcher {
  final List<String> dispatchedIntents = [];

  @override
  Future<bool> launchIntent(DestinationActionType type, String target) async {
    dispatchedIntents.add('${type.name}:$target');
    return true;
  }
}

/// The sole execution gateway to external Android intents.
///
/// Invariants:
/// - Sole pathway: no scanner, tile, notification, or deep link can trigger external actions.
/// - SUSPICIOUS verdicts are strictly blocked by default; ordinary override is forbidden.
/// - UNKNOWN verdicts require explicit two-step user confirmation.
/// - Single-use tokens prevent double-tap, race conditions, and replay.
class ActionGateway {
  final PlatformActionDispatcher dispatcher;
  final Set<String> _usedTokenIds = {};

  ActionGateway({PlatformActionDispatcher? dispatcher})
    : dispatcher = dispatcher ?? SafeActionDispatcher();

  /// Creates a short-lived consent token for a specific scan evaluation.
  ConsentToken createToken({
    required String scanId,
    required DestinationActionType actionType,
    required String canonicalTarget,
  }) {
    final tokenId = 'token_${DateTime.now().microsecondsSinceEpoch}_$scanId';
    return ConsentToken(
      tokenId: tokenId,
      scanId: scanId,
      actionType: actionType,
      canonicalTarget: canonicalTarget,
    );
  }

  /// Executes an action proposal subject to state policy and valid consent.
  Future<ActionExecutionResult> executeAction({
    required EvaluationResult evaluation,
    required ConsentToken token,
    bool userConfirmedUnknown = false,
  }) async {
    // 1. Strict blocking of SUSPICIOUS payloads
    if (evaluation.state == EvaluationState.suspicious) {
      return const ActionExecutionResult(
        success: false,
        status: 'BLOCKED',
        message:
            'Action blocked by security policy: Target is classified as SUSPICIOUS.',
      );
    }

    // 2. Strict two-step confirmation for UNKNOWN payloads
    if (evaluation.state == EvaluationState.unknown && !userConfirmedUnknown) {
      return const ActionExecutionResult(
        success: false,
        status: 'REQUIRES_CONFIRMATION',
        message:
            'Action requires explicit two-step confirmation for UNKNOWN target.',
      );
    }

    // 3. Consent Token validity check (prevent TOCTOU, expired tokens, or replay)
    if (_usedTokenIds.contains(token.tokenId) || token.isUsed) {
      return const ActionExecutionResult(
        success: false,
        status: 'STALE_TOKEN',
        message:
            'Consent token has already been used. Duplicate execution rejected.',
      );
    }

    if (token.isExpired) {
      return const ActionExecutionResult(
        success: false,
        status: 'EXPIRED_TOKEN',
        message:
            'Consent token expired. Please re-evaluate target before proceeding.',
      );
    }

    // 4. Mark token as consumed immediately
    token.isUsed = true;
    _usedTokenIds.add(token.tokenId);

    // 5. Dispatch verified intent safely
    try {
      final success = await dispatcher.launchIntent(
        token.actionType,
        token.canonicalTarget,
      );
      if (success) {
        return const ActionExecutionResult(
          success: true,
          status: 'EXECUTED',
          message: 'Action executed successfully through ActionGateway.',
        );
      } else {
        return const ActionExecutionResult(
          success: false,
          status: 'ERROR',
          message: 'Platform failed to launch requested destination intent.',
        );
      }
    } catch (e) {
      return ActionExecutionResult(
        success: false,
        status: 'ERROR',
        message: 'Execution error: $e',
      );
    }
  }
}
