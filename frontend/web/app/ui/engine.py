"""Declarative, extendable form engine (goal 9).

A form is defined in ``config/forms/<id>.yaml`` and rendered by the generic
macro ``components/form.html``. To reuse the engine in another application,
either add another YAML file there, or subclass :class:`Form` and override
``form_id`` / ``spec`` / validation hooks in Python. No per-application HTML.
"""

from __future__ import annotations

from typing import Any, ClassVar
from urllib.parse import urlparse

from app.core.config import FieldSpec, FormSpec, Settings


class ValidationError:
    """A single field-level error; message resolved from i18n by key."""

    def __init__(self, key: str, **kwargs: Any) -> None:
        self.key = key
        self.kwargs = kwargs


class Form:
    """Base class. Subclasses may override ``form_id`` or inject a custom spec."""

    form_id: ClassVar[str | None] = None
    spec: FormSpec

    def __init__(self, settings: Settings, spec: FormSpec | None = None) -> None:
        self.settings = settings
        resolved_id = self.form_id or (spec.id if spec else None)
        if spec is not None:
            self.spec = spec
        elif resolved_id and resolved_id in settings.forms:
            self.spec = settings.forms[resolved_id]
        elif resolved_id is None and len(settings.forms) == 1:
            # No id given and the config defines exactly one form: use it.
            self.spec = next(iter(settings.forms.values()))
        else:
            raise LookupError(f"Form spec not found: {resolved_id!r}")

    # -- rendering -----------------------------------------------------------

    def field(self, name: str) -> FieldSpec:
        return next(f for f in self.spec.fields if f.name == name)

    @staticmethod
    def _is_visible(field: FieldSpec, values: dict[str, Any]) -> bool:
        """Visibility per the field's condition: `equals` for single-value
        fields, `includes` for multi (checkbox list) fields."""
        cond = field.visible_when
        if cond is None:
            return True
        if cond.equals is not None:
            return values.get(cond.field) == cond.equals
        if cond.includes is not None:
            chosen = values.get(cond.field) or []
            return cond.includes in chosen
        return True

    def visible_fields(self, values: dict[str, Any]) -> list[FieldSpec]:
        return [f for f in self.spec.fields if self._is_visible(f, values)]

    def default_values(self) -> dict[str, Any]:
        return {f.name: f.default for f in self.spec.fields if f.default is not None}

    # -- validation ----------------------------------------------------------

    def validate(
        self, raw: dict[str, Any], files: list[Any] | None = None
    ) -> tuple[dict[str, Any], dict[str, ValidationError]]:
        """Validate raw form values (and uploaded files) against the spec.

        Returns ``(clean, errors)`` where errors maps field name to error.
        """
        clean: dict[str, Any] = {}
        errors: dict[str, ValidationError] = {}
        file_field_types = {"file-multi", "folder"}
        for field in self.visible_fields(raw):
            value = raw.get(field.name)
            file_args = files if field.type in file_field_types else None
            error = self._validate_field(field, value, file_args)
            if error is not None:
                errors[field.name] = error
            elif field.multi:
                clean[field.name] = [str(v) for v in (value or [])]
            else:
                clean[field.name] = value
        return clean, errors

    def _validate_field(
        self, field: FieldSpec, value: Any, files: list[Any] | None
    ) -> ValidationError | None:
        if field.type == "file-multi":
            return self._validate_files(field, files or [])
        if field.multi:
            return self._validate_multi(field, value or [])
        if field.required and not value:
            return ValidationError("errors.required")
        validators = field.validators
        if value and validators.max_length and len(str(value)) > validators.max_length:
            return ValidationError("errors.too_long", limit=validators.max_length)
        if value and field.type == "url" and validators.allowed_hosts:
            host = urlparse(str(value)).hostname
            if not host or host.lower() not in [h.lower() for h in validators.allowed_hosts]:
                return ValidationError("errors.bad_url")
        if value and field.choices:
            error = self._check_choice(field, str(value))
            if error is not None:
                return error
        return None

    def _validate_multi(self, field: FieldSpec, values: list[Any]) -> ValidationError | None:
        if field.required and not values:
            return ValidationError("errors.required")
        for value in values:
            error = self._check_choice(field, str(value))
            if error is not None:
                return error
        return None

    def _check_choice(self, field: FieldSpec, value: str) -> ValidationError | None:
        allowed = {c["value"] for c in field.choices}
        if value not in allowed:
            return ValidationError("errors.bad_choice")
        disabled = {c["value"] for c in field.choices if c.get("disabled")}
        if value in disabled:
            return ValidationError("errors.unavailable_choice")
        return None

    def _validate_files(self, field: FieldSpec, files: list[Any]) -> ValidationError | None:
        if field.required and not files:
            return ValidationError("errors.empty_upload")
        limit = field.validators.max_files
        if limit and len(files) > limit:
            return ValidationError("errors.too_many_files", limit=limit)
        return None
