import { forwardRef, useRef } from "react";
import { PCAP_FILE_TYPES } from "../api";

interface Props {
  label: string;
  onFile: (file: File) => void;
  disabled?: boolean;
  className?: string;
}

export const FilePickerButton = forwardRef<HTMLButtonElement, Props>(function FilePickerButton(
  { label, onFile, disabled, className },
  ref,
) {
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <>
      <button
        ref={ref}
        type="button"
        className={className}
        disabled={disabled}
        onClick={() => inputRef.current?.click()}
      >
        {label}
      </button>
      <input
        ref={inputRef}
        type="file"
        accept={PCAP_FILE_TYPES}
        hidden
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
    </>
  );
});
