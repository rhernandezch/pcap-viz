import { FilePickerButton } from "./FilePickerButton";

interface Props {
  onFile: (file: File) => void;
  disabled: boolean;
}

export function DropZone({ onFile, disabled }: Props) {
  return (
    <div className="dropzone">
      <h1 className="big">Open a SIP capture</h1>
      <p>Drop a .pcap or .pcapng anywhere, or choose a file. Parsing happens on this machine.</p>
      <FilePickerButton label="Choose file" onFile={onFile} disabled={disabled} />
      <p className="hint">Press ? for keyboard shortcuts</p>
    </div>
  );
}
