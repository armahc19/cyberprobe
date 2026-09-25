"""Task queue for multi-step investigations."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

TASK_STATUSES = ("queued", "running", "completed", "failed", "blocked")


@dataclass
class InvestigationTask:
    name: str
    phase: str
    task_id: str = field(default_factory=lambda: uuid4().hex[:12])
    status: str = "queued"
    depends_on: tuple[str, ...] = ()
    attempts: int = 0
    error: str | None = None
    result: dict | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def transition(self, status: str, *, error: str | None = None, result: dict | None = None) -> None:
        if status not in TASK_STATUSES:
            raise ValueError(f"Unknown task status: {status}")
        self.status, self.error, self.result = status, error, result
        self.updated_at = datetime.now(timezone.utc).isoformat()


class TaskManager:
    def __init__(self):
        self.tasks: dict[str, InvestigationTask] = {}

    def add(self, name: str, phase: str, depends_on: tuple[str, ...] = ()) -> InvestigationTask:
        task = InvestigationTask(name=name, phase=phase, depends_on=depends_on)
        self.tasks[task.task_id] = task
        return task

    def add_plan(self, phases: list[str] | tuple[str, ...]) -> list[InvestigationTask]:
        created, previous = [], None
        for phase in phases:
            task = self.add(phase, phase, (previous,) if previous else ())
            created.append(task)
            previous = task.task_id
        return created

    def _dependencies_done(self, task: InvestigationTask) -> bool:
        return all(self.tasks[task_id].status == "completed" for task_id in task.depends_on if task_id in self.tasks)

    def next(self) -> InvestigationTask | None:
        return next((task for task in self.tasks.values() if task.status == "queued" and self._dependencies_done(task)), None)

    def start_next(self) -> InvestigationTask | None:
        task = self.next()
        if task is None:
            return None
        task.attempts += 1
        task.transition("running")
        return task

    def complete(self, task_id: str, result: dict | None = None) -> InvestigationTask:
        task = self.get(task_id)
        if task.status != "running":
            raise ValueError(f"Only running tasks can complete; current status is {task.status}.")
        task.transition("completed", result=result)
        return task

    def fail(self, task_id: str, error: str, retry: bool = False) -> InvestigationTask:
        task = self.get(task_id)
        if task.status != "running":
            raise ValueError(f"Only running tasks can fail; current status is {task.status}.")
        task.transition("queued" if retry else "failed", error=error)
        return task

    def block_unrunnable(self) -> list[InvestigationTask]:
        blocked = []
        for task in self.tasks.values():
            if task.status == "queued" and any(self.tasks.get(dep) and self.tasks[dep].status in {"failed", "blocked"} for dep in task.depends_on):
                task.transition("blocked", error="A prerequisite task failed or is blocked.")
                blocked.append(task)
        return blocked

    def get(self, task_id: str) -> InvestigationTask:
        if task_id not in self.tasks:
            raise ValueError(f"Unknown task: {task_id}")
        return self.tasks[task_id]

    def summary(self) -> dict[str, int]:
        return {status: sum(task.status == status for task in self.tasks.values()) for status in TASK_STATUSES}
