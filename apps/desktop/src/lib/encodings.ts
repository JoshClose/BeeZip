// Name encodings (docs/M5.md §6, §8.4): how names an archive stores as bytes are read. A tab
// can choose one; otherwise the engine uses `[names] encoding` from the settings.
import type { NameEncoding } from "../gen/commands";

export const NAME_ENCODINGS: { id: NameEncoding; label: string }[] = [
  { id: "auto", label: "Auto: UTF-8, else Windows' code page" },
  { id: "utf-8", label: "UTF-8" },
  { id: "cp437", label: "DOS, US (437)" },
  { id: "cp850", label: "DOS, Western Europe (850)" },
  { id: "cp852", label: "DOS, Central Europe (852)" },
  { id: "cp866", label: "DOS, Cyrillic (866)" },
  { id: "cp932", label: "Japanese, Shift-JIS (932)" },
  { id: "euc-jp", label: "Japanese, EUC-JP" },
  { id: "cp936", label: "Chinese Simplified, GBK (936)" },
  { id: "gb18030", label: "Chinese Simplified, GB18030" },
  { id: "cp950", label: "Chinese Traditional, Big5 (950)" },
  { id: "cp949", label: "Korean (949)" },
  { id: "cp874", label: "Thai (874)" },
  { id: "cp1250", label: "Windows, Central Europe (1250)" },
  { id: "cp1251", label: "Windows, Cyrillic (1251)" },
  { id: "cp1252", label: "Windows, Western Europe (1252)" },
  { id: "cp1253", label: "Windows, Greek (1253)" },
  { id: "cp1254", label: "Windows, Turkish (1254)" },
  { id: "cp1255", label: "Windows, Hebrew (1255)" },
  { id: "cp1256", label: "Windows, Arabic (1256)" },
  { id: "cp1257", label: "Windows, Baltic (1257)" },
  { id: "cp1258", label: "Windows, Vietnamese (1258)" },
  { id: "koi8-r", label: "Cyrillic, KOI8-R" },
  { id: "koi8-u", label: "Cyrillic, KOI8-U" },
  { id: "iso-8859-1", label: "Latin-1 (ISO 8859-1)" },
  { id: "iso-8859-2", label: "Latin-2 (ISO 8859-2)" },
  { id: "iso-8859-5", label: "Cyrillic (ISO 8859-5)" },
  { id: "iso-8859-7", label: "Greek (ISO 8859-7)" },
];

export function encodingLabel(id: NameEncoding): string {
  return NAME_ENCODINGS.find((e) => e.id === id)?.label ?? id;
}
