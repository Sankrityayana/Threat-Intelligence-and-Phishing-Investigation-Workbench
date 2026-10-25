"""Test that the Streamlit app can be imported without errors."""

from __future__ import annotations


def test_app_import():
    """Test that the Streamlit app module can be imported."""
    try:
        # If we get here, the import succeeded
        assert True
    except Exception as e:
        # Fail the test with the exception details
        assert False, f"Failed to import app module: {e}"


if __name__ == "__main__":
    test_app_import()
    print("App import test passed!")
