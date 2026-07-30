import {
  Form,
  FormSubmission,
  OtpRequest,
  OtpVerify,
  FieldType,
  FieldValue,
  BlindSubmission,
  FormResults,
  UserForms,
  ParticipantMode
} from './generated/forms';

export type {
  Form as FormType,
  FormSubmission as FormSubmissionType,
  OtpRequest as OtpRequestType,
  OtpVerify as OtpVerifyType,
  FieldValue,
  BlindSubmission as BlindSubmissionType,
  FormResults as FormResultsType,
  UserForms as UserFormsType
};

export { FieldType, ParticipantMode };

export function encodeForm(payload: Form): Uint8Array {
  return Form.encode(payload).finish();
}

const isDev = import.meta.env.DEV;

function logDev(messageType: string, decoded: any) {
  if (isDev) {
    console.log(`[Proto Debug] Decoded ${messageType}:`, decoded);
  }
}

export function decodeForm(buffer: Uint8Array): Form {
  const decoded = Form.decode(buffer);
  logDev('Form', decoded);
  return decoded;
}

export function encodeFormSubmission(payload: FormSubmission): Uint8Array {
  return FormSubmission.encode(payload).finish();
}

export function decodeFormSubmission(buffer: Uint8Array): FormSubmission {
  const decoded = FormSubmission.decode(buffer);
  logDev('FormSubmission', decoded);
  return decoded;
}

export function encodeBlindSubmission(payload: BlindSubmission): Uint8Array {
  return BlindSubmission.encode(payload).finish();
}

export function decodeFormResults(buffer: Uint8Array): FormResults {
  const decoded = FormResults.decode(buffer);
  logDev('FormResults', decoded);
  return decoded;
}

export function decodeUserForms(buffer: Uint8Array): UserForms {
  const decoded = UserForms.decode(buffer);
  logDev('UserForms', decoded);
  return decoded;
}

export function encodeOtpRequest(payload: OtpRequest): Uint8Array {
  return OtpRequest.encode(payload).finish();
}

export function encodeOtpVerify(payload: OtpVerify): Uint8Array {
  return OtpVerify.encode(payload).finish();
}

export function formSubmissionToJson(sub: FormSubmission): any {
  return FormSubmission.toJSON(sub);
}