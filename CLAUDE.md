# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a curated knowledge repository containing:
- **Links and resources** for software engineering learning (README.md)
- **AI workflow process notes** documenting development philosophies (ai_workflow_process_notes/)
- **Custom Claude Code agents and commands** for specialized workflows (claude_code_agents_commands/)

This repository is NOT a code project - it's a documentation and reference repository with no build, test, or deployment workflows.

## Repository Structure

```
useful-links-and-resources/
├── README.md                          # Curated links for software development
├── ai_workflow_process_notes/         # Development methodology notes
│   └── notes.md                       # Core workflow philosophy
└── claude_code_agents_commands/       # Claude Code extensions
    ├── agents/                        # 6 specialized agents
    └── commands/                      # 24 custom slash commands
```

## Core Development Philosophy

From ai_workflow_process_notes/notes.md:
1. **Documentation-First**: Write docs and specs before implementation
2. **Research & Planning are Critical**: Align research/plans with goals before building
3. **Test-Driven Development**: Start with failing tests, then implement features
4. **AI-First Implementation**: Let AI handle implementation after thorough planning

## Claude Code Custom Extensions

This repository contains a rich set of custom agents and commands designed for sophisticated software development workflows.

### Custom Agents (claude_code_agents_commands/agents/)

Located agents understand specific aspects of codebases:

- **codebase-analyzer.md**: Analyzes implementation details, traces data flow, documents how code works with file:line references
- **codebase-locator.md**: Finds files and code relevant to specific tasks
- **codebase-pattern-finder.md**: Identifies similar patterns and implementations to model after
- **thoughts-analyzer.md**: Extracts insights from documentation and research
- **thoughts-locator.md**: Finds existing research, plans, and decisions
- **web-search-researcher.md**: Performs focused web research

### Custom Commands (claude_code_agents_commands/commands/)

24 specialized commands for various workflows including:

**Planning & Research:**
- `/create_plan` - Interactive plan creation through research and iteration (uses Opus model)
- `/validate_plan` - Validates implementation plans
- `/implement_plan` - Executes approved plans phase-by-phase with verification

**Workflow Commands:**
- `/founder_mode` - Creates Linear tickets and PRs for experimental features post-implementation
- `/debug` - Debugging workflow
- `/local_review` - Local code review process

**Git & CI Commands:**
- `/ci_commit` - CI-specific commit workflow
- `/ci_describe_pr` - PR description for CI
- `/create_worktree` - Git worktree creation

**Research Commands:**
- `/research_codebase_generic` - Generic codebase research
- `/research_codebase_nt` - NT-specific codebase research
- `/research_codebase` - Standard codebase research

**Other Commands:**
- `/ralph_plan`, `/ralph_research`, `/ralph_impl` - Ralph-specific workflows
- `/oneshot_plan`, `/oneshot` - Quick one-off implementations
- `/create_handoff`, `/resume_handoff` - Handoff workflows
- `/linear` - Linear ticket integration
- `/commit`, `/describe_pr` - Standard git workflows

## Key Workflow Patterns

### Research-First Approach
When exploring codebases, spawn parallel research agents:
- Use **codebase-locator** to find relevant files
- Use **codebase-analyzer** to understand implementations
- Use **thoughts-locator** to find existing documentation
- Read ALL identified files fully before proceeding

### Planning Methodology
From create_plan.md workflow:
1. Read context files COMPLETELY (no partial reads)
2. Spawn parallel research tasks to gather context
3. Verify understanding through code investigation
4. Create detailed phase-based plans with automated + manual verification criteria
5. NO open questions in final plans - resolve everything first

### Implementation Approach
From implement_plan.md workflow:
1. Read plan and all referenced files fully
2. Implement phases sequentially
3. Run automated verification after each phase
4. Pause for manual verification before proceeding
5. Update checkboxes in plan as work completes

### Success Criteria Structure
Always separate into:
- **Automated Verification**: Commands, tests, compilation checks
- **Manual Verification**: UI testing, performance validation, edge cases

## Working with This Repository

### Common Operations

**Adding new resources:**
```bash
# Edit README.md to add links in appropriate sections
# Commit changes
git add README.md
git commit -m "feat: add [resource description]"
```

**Adding workflow notes:**
```bash
# Add notes to ai_workflow_process_notes/notes.md
# Or create new markdown files in that directory
```

**Creating custom agents/commands:**
```bash
# Add agent definitions to claude_code_agents_commands/agents/
# Add command definitions to claude_code_agents_commands/commands/
# Follow YAML frontmatter format shown in existing files
```

### Git Workflow

Main branch: `main`

Standard workflow:
```bash
git status                          # Check current state
git add <files>                     # Stage changes
git commit -m "type: description"   # Commit with conventional format
git push                            # Push to remote
```

## Custom Agent/Command Format

Agents and commands use YAML frontmatter:

```markdown
---
name: agent-name (for agents)
description: Brief description
tools: Tool1, Tool2 (for agents)
model: sonnet|opus (optional)
---

[Detailed instructions in markdown]
```

## Links Repository Categories

The README.md organizes resources into:
- Web Development, Deep Learning, Backend Engineering
- Auth Implementation, Software Engineering Mindset
- AI Frameworks & Agents
- React, REST API, Production Best Practices
- System Design, Modern SaaS
- Programming Languages (Go, Python, TypeScript, JavaScript)
- API patterns, Career guidance, Understanding codebases

When adding resources, maintain this categorical structure.
