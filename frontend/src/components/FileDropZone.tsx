import { type FC, type DragEvent, type ChangeEvent, useRef, useState } from 'react'
import { Upload } from 'lucide-react'

interface Props {
  onFile: (f: File) => void
  disabled?: boolean
}

const ACCEPTED = '.pdf,.docx,.txt,.eml'

const FileDropZone: FC<Props> = ({ onFile, disabled }) => {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function handleDrop(e: DragEvent) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) onFile(f)
  }

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (f) onFile(f)
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      className={`
        flex flex-col items-center justify-center gap-2 p-6 rounded-xl border-2 border-dashed
        cursor-pointer transition-all duration-200
        ${dragging ? 'border-blue-500 bg-blue-950/30' : 'border-slate-600 hover:border-slate-500 bg-slate-800/30'}
        ${disabled ? 'opacity-40 pointer-events-none' : ''}
      `}
    >
      <Upload size={24} className="text-slate-400" />
      <div className="text-center">
        <p className="text-sm text-slate-300">Drop file here or click to browse</p>
        <p className="text-xs text-slate-500 mt-1">PDF · DOCX · TXT · EML — max 10 MB</p>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED}
        onChange={handleChange}
        className="hidden"
        disabled={disabled}
      />
    </div>
  )
}

export default FileDropZone
