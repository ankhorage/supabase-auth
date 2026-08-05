from pathlib import Path

path = Path('src/oauthAttemptLifecycle.test.ts')
text = path.read_text()
text = text.replace(
    'adapter.startAuthorization({',
    'adapter.startAuthorization.call(adapter, {',
)
text = text.replace(
    'adapter.completeAuthorization({',
    'adapter.completeAuthorization.call(adapter, {',
)
text = text.replace(
    """    setNow(value: number) {
      currentTime = value;
    },
""",
    """    setNow: (value: number) => {
      currentTime = value;
    },
""",
)
path.write_text(text)
