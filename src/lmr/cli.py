import argparse

from lmr import __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lmr",
        description="Lateral Movement Reconstructor (lmr) - Automated DFIR network analysis.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.parse_args()
    print("lmr core initialized. Use --help for options.")


if __name__ == "__main__":
    main()