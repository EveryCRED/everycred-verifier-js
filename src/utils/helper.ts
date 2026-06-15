import { ProcessStepStatus } from "../models/common.model";

export function logDiagnosticStep(input: ProcessStepStatus, credential: unknown) {
    const { step, title, status, reason } = input;
    const success = "color: #22c55e; font-weight: bold;"; // green
    const fail = "color: #ef4444; font-weight: bold;"; // red
    const label = "color: #0ea5e9; font-weight: bold;"; // blue
    const value = "color: #F59E0B;"; // yellow
    const header = "color: white; background: #6366f1; padding: 2px 6px; font-weight:bold;";
    const border = "color: #22d3ee; font-weight: bold;";

    const statusStyle = status ? success : fail;
    const statusText = status ? "SUCCESS" : "FAILED";

    console.log("%c┌──────────────────────────────────────────────────────┐", border);
    console.log("%c│   SD Credential Verification Progress                │", header);
    console.log("%c├──────────────────────────────────────────────────────┤", border);

    console.log("%c│ Step    : %c" + step, label, value);
    console.log("%c│ Title   : %c" + title, label, value);
    console.log("%c│ Status  : %c" + statusText, label, statusStyle);
    console.log("%c│ Reason  : %c" + reason, label, value);

    console.log("%c└──────────────────────────────────────────────────────┘", border);

    console.log("%cCredential Snapshot:", "color:#0ea5e9; font-weight:bold;", credential);
}