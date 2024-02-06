export interface ResponseMessage {
  message: string;
  status: boolean;
}

export interface ProcessStepStatus {
  step: string,
  title: string,
  status: boolean,
  reason: string;
}