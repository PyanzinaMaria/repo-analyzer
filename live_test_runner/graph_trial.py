"""Live interaction graph built by executing actions against an HTTP target."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from math import sqrt
from urllib.parse import urlparse

from .actions import Action, actions_in
from .detectors import ProblemReport, inspect_response
from .http_client import LiveClient, Observation

START = "hub"
# Strip volatile tokens so CSRF/session noise does not explode the state graph.
_VOLATILE_HTML = re.compile(
    r'(name=["\']csrfmiddlewaretoken["\']\s+value=["\'])[^"\']*',
    re.IGNORECASE,
)
_VOLATILE_META = re.compile(
    r'(csrf-token["\']\s+content=["\'])[^"\']*',
    re.IGNORECASE,
)


def _stable_html(html: str) -> str:
    cleaned = _VOLATILE_HTML.sub(r"\1", html)
    return _VOLATILE_META.sub(r"\1", cleaned)


class LiveTrial:
    """Learner-facing contract backed by live HTTP observations."""

    def __init__(self, client: LiveClient, budget: int, horizon: int) -> None:
        if budget < 1 or horizon < 1:
            raise ValueError("budget and horizon must be positive")
        self.client = client
        self.budget = budget
        self.horizon = horizon
        self.steps = 0
        self.counts: Counter = Counter()
        self.nodes: dict[str, tuple[tuple[Action, ...], str, int]] = {}
        self.edges: dict[tuple[str, int, str], int] = {}
        self.examples: dict[str, tuple] = {}
        self.checkpoints: list[dict] = []
        self.checkpoint_steps = {i * budget // 4 for i in range(1, 5)}
        self.problems = ProblemReport()
        self.episodes = 0
        self.proof_pages: set[str] = set()
        self._page_of: dict[str, str] = {}
        self._start_html_hash: str | None = None
        self._last_state = self.begin_episode()
        self.counts[START] = 1
        self.snapshot()

    @property
    def state(self) -> str:
        return self._last_state

    def _page_from(self, observation: Observation) -> str:
        path = observation.page_path or urlparse(observation.url).path or "/"
        return path.split("?", 1)[0] or "/"

    def _identity(self, observation: Observation, *, force_start: bool = False) -> tuple[str, str]:
        page = self._page_from(observation)
        digest = hashlib.sha256(
            _stable_html(observation.html).encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
        if force_start:
            self._start_html_hash = digest
            return START, page
        if self._start_html_hash and digest == self._start_html_hash:
            return START, page
        return digest, page

    def observe(self, observation: Observation, *, force_start: bool = False) -> str:
        inspect_response(
            self.problems,
            status_code=observation.status_code,
            headers=observation.headers,
            body=observation.html,
            url=observation.url,
            submitted_values=observation.submitted_values,
            page_path=self._page_from(observation),
        )
        identity, page = self._identity(observation, force_start=force_start)
        if page.lstrip("/") in ("text-proof", "screen-proof", "print-proof"):
            self.proof_pages.add(page)
        if identity not in self.nodes:
            actions = actions_in(observation.html, current_path=page)
            self.nodes[identity] = (actions, observation.html, self.steps)
            self._page_of[identity] = page
        return identity

    def actions(self, state: str):
        return range(len(self.nodes[state][0]))

    def action_list(self, state: str) -> tuple[Action, ...]:
        return self.nodes[state][0]

    def begin_episode(self) -> str:
        """Free reset to the start state between episodes."""
        self.episodes += 1
        observation = self.client.reset()
        identity = self.observe(observation, force_start=True)
        # Ensure START node always holds the latest start-page action list.
        start_page = self._page_from(observation)
        actions = actions_in(observation.html, current_path=start_page)
        self.nodes[START] = (actions, observation.html, self.nodes.get(START, ((), "", 0))[2])
        self._page_of[START] = start_page
        self._last_state = START
        return START

    def step(self, state: str, action: int, path: list) -> tuple[str, float]:
        assert self.steps < self.budget
        actions = self.nodes[state][0]
        if not actions:
            # No-op burn if a terminal state was selected; should be rare.
            self.steps += 1
            if self.steps in self.checkpoint_steps:
                self.snapshot()
            return state, 1.0 / sqrt(max(1, self.counts[state]))
        chosen = actions[action % len(actions)]
        self.steps += 1
        observation = self.client.execute(chosen)
        nxt = self.observe(observation)
        self.edges.setdefault((state, action, nxt), self.steps)
        self.counts[nxt] += 1
        if nxt != START:
            self.examples.setdefault(nxt, (*path, action))
        if self.steps in self.checkpoint_steps:
            self.snapshot()
        self._last_state = nxt
        return nxt, 1.0 / sqrt(self.counts[nxt])

    def snapshot(self) -> None:
        self.checkpoints.append(
            dict(
                step=self.steps,
                states=len(self.nodes),
                discovered_actions=sum(len(a) for a, _, _ in self.nodes.values()),
                transitions=len(self.edges),
                proofs=len(self.proof_pages),
                problems_total=self.problems.problems_total,
                problems_unique=self.problems.problems_unique,
            )
        )

    def export_graph(self) -> dict:
        return dict(
            checkpoints=self.checkpoints,
            nodes=[
                dict(
                    id=node,
                    page=self._page_of.get(node, ""),
                    discovered_at=seen_at,
                    actions=[
                        dict(index=i, name=action.describe())
                        for i, action in enumerate(actions)
                    ],
                )
                for node, (actions, _, seen_at) in self.nodes.items()
            ],
            edges=[
                dict(source=source, action=index, target=target, first_used_at=step)
                for (source, index, target), step in self.edges.items()
            ],
            proof_pages=sorted(self.proof_pages),
        )

    def metrics(self) -> dict:
        last = self.checkpoints[-1] if self.checkpoints else {}
        return dict(
            steps=self.steps,
            episodes=self.episodes,
            states=len(self.nodes),
            discovered_actions=sum(len(a) for a, _, _ in self.nodes.values()),
            transitions=len(self.edges),
            proofs=len(self.proof_pages),
            proof_pages=sorted(self.proof_pages),
            **self.problems.as_dict(),
            checkpoints=self.checkpoints,
            final_checkpoint=last,
        )
