// "Run setup.exe from a.zip?" (docs/M5.md §8.3): a program opened from an archive asks first.
// Cancel has the focus, so Enter doesn't run it.
import { Play } from "lucide-react";
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { useOpened } from "../../lib/opened";

export function RunPrompt() {
  const q = useOpened((s) => s.asking);
  if (!q) return null;
  return (
    <Dialog
      open
      dismissable={false}
      onClose={() => q.answer(false)}
      title={`Run ${q.name} from ${q.archive}?`}
      description="Programs from archives can harm your computer. Windows checks it first, as it does a download."
      footer={
        <>
          <Button autoFocus onClick={() => q.answer(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => q.answer(true)}>
            <Play /> Run
          </Button>
        </>
      }
    >
      <span />
    </Dialog>
  );
}
