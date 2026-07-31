# Role-Specific LLM Agents for Urban Rail Depot Scheduling

This repository implements a role-specific LLM agent system for dynamic
urban rail depot scheduling. Four agents represent OCC line operations and DCC
departure, arrival, and proactive-shunting functions. They interpret operating
events, coordinate resource decisions, and construct executable operating
plans.

## Functions

- Understands operating events and depot states.
- Coordinates OCC and DCC decisions across trainsets, routes, tracks, and time
  windows.
- Generates departure, arrival, and proactive-shunting actions.
- Revises affected operations through cross-role interaction.
- Applies independent safety admission.
- Produces structured operating plans and complete successor states.
