// "readme.txt was changed. Update it in a.zip?" (docs/M5.md §8.3): one question at a time, for
// files opened from a tab and changed in their apps.
import { RefreshCw } from "lucide-react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { useArchives } from "../../lib/archives";
import { baseName } from "../../lib/format";
import { notNow, updateEntry, useOpened } from "../../lib/opened";
import { toastError } from "../../lib/toasts";

export function ChangedPrompt() {
  const file = useOpened((s) => s.changed[0]);
  const tab = useArchives((s) => (file ? s.tabs.find((t) => t.id === file.tab) : undefined));
  if (!file || !tab) return null;
  const name = baseName(file.entry);
  const update = () => updateEntry(file).catch((e) => toastError(e, `Updating ${name}`));
  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => notNow(file)}
      title={`${name} was changed`}
      description={`Update it in ${tab.name}?`}
      footer={
        <>
          <Button onClick={() => notNow(file)}>Not now</Button>
          <Button variant="primary" onClick={() => void update()}>
            <RefreshCw /> Update
          </Button>
        </>
      }
    >
      <p className="selectable pb-1 text-[12px] break-all text-muted">{file.path}</p>
    </Dialog>
  );
}
