import click
from rich.console import Console

from .core.engine import RedTeamEngine

console = Console()


@click.group()
def main():
    """NeuroRedKit CLI."""
    pass


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=False), help="Path to YAML config")
def run(config_path: str | None):
    """Run a red team simulation."""
    engine = RedTeamEngine(config_path=config_path)
    result = engine.run()
    console.print("[green]Run complete[/green]")
    console.print(result)


if __name__ == "__main__":
    main()
