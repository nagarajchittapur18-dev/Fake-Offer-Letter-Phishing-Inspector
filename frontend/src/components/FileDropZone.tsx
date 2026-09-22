import React, { useCallback, useRef, useState } from 'react'
import { Upload, X, FileText, FileType } from 'lucide-react'

interface FileDropZoneProps {
  onFile: (file: File | null) => void
  file:   File | null
}

const MAX_SIZE = 10 * 1024 * 1024 // 10 MB
const ACCEPTED = ['.pdf', '.docx', '.txt', '.eml']
const MIME_OK  = new Set([
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/plain',
  'message/rfc822',
])

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`
  if (b < 1_048_576) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1_048_576).toFixed(1)} MB`
}

function extBadge(name: string) {
  const ext = name.split('.').pop()?.toUpperCase() ?? 'FILE'
  const colors: Record<string, string> = {
    PDF:  'bg-red-900/60 text-red-300 border-red-700',
    DOCX: 'bg-blue-900/60 text-blue-300 border-blue-700',
    TXT:  'bg-slate-700 text-slate-300 border-slate-600',
    EML:  'bg-violet-900/60 text-violet-300 border-violet-700',
  }
  return colors[ext] ?? 'bg-slate-700 text-slate-300 border-slate-600'
}

export const FileDropZone: React.FC<FileDropZoneProps> = ({ onFile, file }) => {
  const inputRef    = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  const [err,  setErr]  = useState<string | null>(null)

  const validate = (f: File): string | null => {
    if (f.size > MAX_SIZE)
      return `File too large (${formatBytes(f.size)}). Max 10 MB.`
    const ext = '.' + f.name.split('.').pop()?.toLowerCase()
    if (!ACCEPTED.includes(ext) && !MIME_OK.has(f.type))
      return `Unsupported type "${ext}". Accepted: PDF, DOCX, TXT, EML.`
    return null
  }

  const handle = (f: File) => {
    const e = validate(f)
    if (e) { setErr(e); return }
    setErr(null)
    onFile(f)
  }

  const onDrop = useCallback((ev: React.DragEvent) => {
    ev.preventDefault(); setDrag(false)
    const f = ev.dataTransfer.files[0]
    if (f) handle(f)
  }, [])

  if (file) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-slate-600 bg-slate-800/60 px-4 py-3">
        <FileText className="w-8 h-8 text-slate-400 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">{file.name}</p>
          <div className="flex items-center gap-2 mt-0.5">
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${extBadge(file.name)}`}>
              {file.name.split('.').pop()?.toUpperCase()}
            </span>
            <span className="text-xs text-slate-500">{formatBytes(file.size)}</span>
          </div>
        </div>
        <button onClick={() => { onFile(null); setErr(null) }}
          className="flex-shrink-0 p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-red-400 transition">
          <X className="w-4 h-4" />
        </button>
      </div>
    )
  }

  return (
    <div>
      <div
        onDragOver={e => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition
          ${drag ? 'border-violet-500 bg-violet-950/30' : 'border-slate-700 hover:border-slate-500 bg-slate-900/40'}`}
      >
        <Upload className={`w-8 h-8 mx-auto mb-3 ${drag ? 'text-violet-400' : 'text-slate-600'}`} />
        <p className="text-sm font-medium text-slate-300">
          Drop your file here, or <span className="text-violet-400 underline underline-offset-2">browse</span>
        </p>
        <p className="text-xs text-slate-600 mt-1.5">PDF · DOCX · TXT · EML · max 10 MB</p>
        <input
          ref={inputRef}
          type="file"
          accept=".pdf,.docx,.txt,.eml"
          className="hidden"
          onChange={e => { const f = e.target.files?.[0]; if (f) handle(f) }}
        />
      </div>
      {err && (
        <p className="mt-2 text-xs text-red-400 flex items-center gap-1.5">
          <FileType className="w-3.5 h-3.5 flex-shrink-0" />{err}
        </p>
      )}
    </div>
  )
}
