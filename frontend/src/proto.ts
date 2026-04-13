import protobuf from 'protobufjs';
import formsProto from './forms.proto?raw';

const root = protobuf.parse(formsProto).root;

export const Form = root.lookupType('Form');
export const FormSubmission = root.lookupType('FormSubmission');
export const FieldType = root.lookupEnum('FieldType').values;
export const OtpRequest = root.lookupType('OtpRequest');
export const OtpVerify = root.lookupType('OtpVerify');
export const EmailVerificationRequest = root.lookupType('EmailVerificationRequest');
export const EmailVerificationVerify = root.lookupType('EmailVerificationVerify');

export function encodeForm(payload: any): Uint8Array {
  const message = Form.create(payload);
  return Form.encode(message).finish();
}

export function decodeForm(buffer: Uint8Array): any {
  return Form.decode(buffer);
}

export function encodeFormSubmission(payload: any): Uint8Array {
  const message = FormSubmission.create(payload);
  return FormSubmission.encode(message).finish();
}

export function decodeFormSubmission(buffer: Uint8Array): any {
  return FormSubmission.decode(buffer);
}

export function encodeOtpRequest(payload: any): Uint8Array {
  const message = OtpRequest.create(payload);
  return OtpRequest.encode(message).finish();
}

export function encodeOtpVerify(payload: any): Uint8Array {
  const message = OtpVerify.create(payload);
  return OtpVerify.encode(message).finish();
}

export function encodeEmailVerificationRequest(payload: any): Uint8Array {
  const message = EmailVerificationRequest.create(payload);
  return EmailVerificationRequest.encode(message).finish();
}

export function encodeEmailVerificationVerify(payload: any): Uint8Array {
  const message = EmailVerificationVerify.create(payload);
  return EmailVerificationVerify.encode(message).finish();
}
