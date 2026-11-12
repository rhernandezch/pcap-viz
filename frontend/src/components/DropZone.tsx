import { useRef, useState } from "react";
import { PCAP_FILE_TYPES } from "../api";

interface Props {
  onFile: (file: File) => void;
  inline?: boolean;
}

export function DropZone({ onFile, inline }: Props) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <label
      className={`dropzone${dragging ? " dragging" : ""}${inline ? " inline" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files?.[0];
        if (file) onFile(file);
      }}
    >
      {!inline && <div className="big">Drop a .pcap or .pcapng</div>}
      {inline && <div>+ Drop another pcap</div>}
      {!inline && <div className="hint">or click to pick a file</div>}
      <input
        ref={inputRef}
        type="file"
        accept={PCAP_FILE_TYPES}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
    </label>
  );
}
