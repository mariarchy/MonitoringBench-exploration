from pathlib import Path
from zipfile import ZipFile

from huggingface_hub import hf_hub_download

DATA_DIR = Path("data/inspect")
DATA_DIR.mkdir(parents=True, exist_ok=True)


# Download the dataset and unzip the final.zip file. Write it to
# data/inspect
def main() -> None:
    zip_path = hf_hub_download(
        repo_id="neur26anonsub/ctrldataset2026",
        filename="final_dataset.zip",
        repo_type="dataset",
    )
    with ZipFile(zip_path) as zf:
        filenames = [info.filename for info in zf.infolist()]
        print(filenames[:10])


if __name__ == "__main__":
    main()
