import { useEffect, useRef, useState } from "react";

export function useWindowFileDrop(onFile: (file: File) => void): boolean {
  const [dragging, setDragging] = useState(false);
  // Read through a ref so the listeners call the latest closure without re-binding.
  const onFileRef = useRef(onFile);
  onFileRef.current = onFile;

  useEffect(() => {
    const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes("Files");

    const onDragOver = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      setDragging(true);
    };
    const onDragLeave = (e: DragEvent) => {
      // dragleave fires at every child boundary; relatedTarget is null only
      // when the cursor actually leaves the window.
      if (e.relatedTarget === null) setDragging(false);
    };
    const onDrop = (e: DragEvent) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer?.files?.[0];
      if (file) onFileRef.current(file);
    };

    window.addEventListener("dragover", onDragOver);
    window.addEventListener("dragleave", onDragLeave);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("dragleave", onDragLeave);
      window.removeEventListener("drop", onDrop);
    };
  }, []);

  return dragging;
}
