"""Verify the two release platforms in a published index or local OCI archive."""
import json
import sys
import tarfile


def platforms(index, load_index):
    for descriptor in index["manifests"]:
        platform = descriptor.get("platform", {})
        if platform.get("os") == "linux":
            yield platform["architecture"]
        elif load_index and descriptor["mediaType"] in {
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        }:
            yield from platforms(load_index(descriptor["digest"]), load_index)


def main(path):
    if path == "-":
        actual = sorted(platforms(json.load(sys.stdin), None))
    else:
        with tarfile.open(path) as image:
            def load_index(digest):
                location = "blobs/" + digest.replace(":", "/", 1) if digest else "index.json"
                with image.extractfile(location) as stream:
                    return json.load(stream)

            actual = sorted(platforms(load_index(None), load_index))

    if actual != ["amd64", "arm64"]:
        raise SystemExit(f"Expected linux/amd64 and linux/arm64, got {actual}")
    print("Verified package platforms: linux/amd64 and linux/arm64")


if __name__ == "__main__":
    main(sys.argv[1])
