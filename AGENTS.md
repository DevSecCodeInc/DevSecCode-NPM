# Agent instructions

Sprints: current sprints are in the shared DevSecCode workspace sprint set (dsc/docs/sprints/), not in this repository. Use the sprints skill there: check the open sprint before starting work and update it as tasks finish.

NPM is deliberately limited to the Core-produced `public-starter` artifact.
Follow `docs/DevSecCode-NPM Core Migration Plan.md` and the applicable refresh
spec. Core alone builds and signs Core artifacts; NPM consumes verified inputs.
Never package full Core or copy private scanner implementations into NPM.

Never push commits, branches, tags, or refs without Matt's explicit authorization
for that specific push in the current conversation. Planning a release does not
authorize publishing or starting external jobs. After an authorized external job
starts, report its identifier and stop unless monitoring was separately requested.
