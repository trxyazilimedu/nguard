/**
 * useValidateSession Hook
 * Validate current session with backend
 */

'use client';

import { useState, useCallback } from 'react';

export interface ValidateResponse {
  valid: boolean;
  session?: {
    user?: string;
    expires?: number;
    role?: string;
    permissions?: string[];
  };
  error?: string;
}

export function useValidateSession() {
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidateResponse | null>(null);

  const validate = useCallback(async (): Promise<ValidateResponse> => {
    setIsValidating(true);
    try {
      const response = await fetch('/api/auth/validate', {
        method: 'GET',
      });

      const result: ValidateResponse = await response.json();
      setValidationResult(result);
      return result;
    } catch (error) {
      const errorResponse: ValidateResponse = {
        valid: false,
        error: error instanceof Error ? error.message : 'Validation failed',
      };
      setValidationResult(errorResponse);
      return errorResponse;
    } finally {
      setIsValidating(false);
    }
  }, []);

  return {
    validate,
    isValidating,
    validationResult,
    isValid: validationResult?.valid ?? false,
  };
}

/**
 * Usage Example:
 *
 * 'use client';
 *
 * import { useValidateSession } from '@/hooks/useValidateSession';
 *
 * export function SessionStatus() {
 *   const { validate, isValidating, isValid, validationResult } = useValidateSession();
 *
 *   return (
 *     <div>
 *       <button onClick={() => validate()} disabled={isValidating}>
 *         {isValidating ? 'Checking...' : 'Check Session'}
 *       </button>
 *
 *       {isValid && (
 *         <p>✅ Session is valid - Expires at: {new Date(validationResult?.session?.expires || 0).toLocaleString()}</p>
 *       )}
 *
 *       {!isValid && validationResult && (
 *         <p>❌ {validationResult.error}</p>
 *       )}
 *     </div>
 *   );
 * }
 */
