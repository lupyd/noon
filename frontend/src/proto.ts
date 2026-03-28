import protobuf from 'protobufjs';
import formsProto from './forms.proto?raw';

const root = protobuf.parse(formsProto).root;

export const Form = root.lookupType('Form');
export const FormSubmission = root.lookupType('FormSubmission');
export const FieldType = root.lookupEnum('FieldType').values;

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
