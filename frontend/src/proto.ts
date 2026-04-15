import {
  Form,
  FormSubmission,
  OtpRequest,
  OtpVerify,
  FieldType,
  FieldValue,
  BlindSubmission,
  FormResults,
  UserForms
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

export function decodeUserForms(buffer: Uint8Array): UserForms {
  return UserForms.decode(buffer);
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