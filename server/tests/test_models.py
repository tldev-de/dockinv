"""§8 – BaseModel error contract (save/delete return None on error, rollback)."""
from models import Image


def test_save_returns_self_and_assigns_id(app):
    image = Image(name="x", repo_digest="x@sha256:1")
    assert image.save() is image
    assert image.id is not None


def test_save_returns_none_on_integrity_error(app):
    Image(name="a", repo_digest="dup@sha256:1").save()
    dup = Image(name="b", repo_digest="dup@sha256:1")  # unique repo_digest -> IntegrityError
    assert dup.save() is None
    assert dup.id is None
    # the data collector relies on exactly this `image.id is None` signal


def test_delete_returns_self_and_removes_row(app):
    image = Image(name="x", repo_digest="x@sha256:2").save()
    image_id = image.id
    assert image.delete() is image
    assert Image.query.get(image_id) is None
