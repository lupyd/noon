import { 
  Form, 
  FormSubmission, 
  OtpRequest, 
  OtpVerify, 
  EmailVerificationRequest, 
  EmailVerificationVerify,
  FieldType,
  FieldValue,
  BlindSubmission,
  FormResults
} from './generated/forms';

export type { 
  Form as FormType, 
  FormSubmission as FormSubmissionType, 
  OtpRequest as OtpRequestType, 
  OtpVerify as OtpVerifyType, 
  EmailVerificationRequest as EmailVerificationRequestType, 
  EmailVerificationVerify as EmailVerificationVerifyType,
  FieldValue,
  BlindSubmission as BlindSubmissionType,
  FormResults as FormResultsType
};

export { FieldType };

export function encodeForm(payload: Form): Uint8Array {
  return Form.encode(payload).finish();
}

export function decodeForm(buffer: Uint8Array): Form {
  return Form.decode(buffer);
}

export function encodeFormSubmission(payload: FormSubmission): Uint8Array {
  return FormSubmission.encode(payload).finish();
}

export function decodeFormSubmission(buffer: Uint8Array): FormSubmission {
  return FormSubmission.decode(buffer);
}

export function encodeBlindSubmission(payload: BlindSubmission): Uint8Array {
  return BlindSubmission.encode(payload).finish();
}

export function decodeFormResults(buffer: Uint8Array): FormResults {
  return FormResults.decode(buffer);
}

export function encodeOtpRequest(payload: OtpRequest): Uint8Array {
  return OtpRequest.encode(payload).finish();
}

export function encodeOtpVerify(payload: OtpVerify): Uint8Array {
  return OtpVerify.encode(payload).finish();
}

export function encodeEmailVerificationRequest(payload: EmailVerificationRequest): Uint8Array {
  return EmailVerificationRequest.encode(payload).finish();
}

export function encodeEmailVerificationVerify(payload: EmailVerificationVerify): Uint8Array {
  return EmailVerificationVerify.encode(payload).finish();
}
