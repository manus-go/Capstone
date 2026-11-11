---
name: frontend-design
description: >-
  Guidance for distinctive, intentional visual design when building new UI or reshaping an existing one.
  Helps with aesthetic direction, typography, and making choices that avoid templated AI defaults.
  Enforces a two-pass workflow: plan tokens and wireframes first with an interactive checkpoint,
  then build production-ready UI using semantic design tokens and modern CSS custom properties.
---

# Frontend Design

Approach this as the design lead at an independent design studio celebrated for giving every client a distinct, unforgettable visual identity that cannot be mistaken for anyone else's.

Your client has already rejected proposals that felt cliché or templated, and is paying for a distinctive point of view: make deliberate, opinionated choices about palette, typography, layout, and interaction that are tailored directly to this brief. Take calculated aesthetic risks whenever justified.

---

## Global Style & Copy Constraints

1. **Language & Spelling**:
   - Write all design planning, documentation, commentary, and user interface copy in British English (e.g. *colour*, *optimise*, *prioritise*, *centre*, *programme*).
2. **Punctuation**:
   - Strictly avoid em dashes (`—`) and en dashes (`–`) used as parenthetical pauses.
   - Use commas, colons, brackets, or clean sentence breaks instead.
3. **Tone & Voice**:
   - Maintain a friendly-professional tone without corporate jargon or generic AI filler.
   - UI copy must be concise, conversational, and direct.

---

## 1. Ground Designs in the Subject Matter

If the brief does not explicitly define what the product or subject matter is, identify it yourself before designing and confirm with the client. Propose one concrete subject, the design's target audience, and the primary job to be done.

The subject's industry, physical materials, history, and cultural vernacular are where authentic visual distinctions originate:
- A digital experience for an artisanal printmaker demands different weight, texture, and rhythm than a telemetry dashboard for aerospace engineers.
- Build with the brief's real content and subject matter throughout; avoid generic placeholder data whenever possible.

---

## 2. Core Design Principles

### Hero Section & First Impressions
The hero is the first thing viewers encounter:
- Open with the most characteristic artifact in the subject's world: a strong headline, a primary interactive demo, an unexpected visual composition, or an architectural layout.
- Avoid the cliché SaaS hero (a massive generic stat number, an adjacent tiny label, and a radial gradient blur background) unless it is genuinely the single best choice for the concept.

### Typography as Personality
Typography carries the soul and temperament of the interface:
- Use one versatile family or two clearly contrasting families (e.g. an expressive display serif paired with an understated geometric sans-serif).
- Set an intentional typographic scale guided by *The Elements of Typographic Style* with deliberate weights, optical widths, and tracking.
- When used for headlines or hero moments, treat the typography as an active compositional element rather than a neutral container for words.
- Keep line lengths for body prose under 80 characters. Serif body text should receive slightly more line height than sans-serif equivalents.
- **Banned AI Typographic Tells**:
  - Never accent a solitary word in a headline with an isolated italic, bold, or colour switch.
  - Avoid all-caps styling for standard form labels and card headings.
  - Do not prepend redundant micro-labels or uppercase category tags above every heading.

### Visual Structure as Information
Structural devices (borders, outlines, dividers, counters, indicators) must encode functional meaning rather than serve as decorative fill:
- Numbered markers (`01`, `02`, `03`) are reserved strictly for genuine sequential processes, timelines, or ordered steps.
- Avoid chopping layouts into repetitive, identical card grids with uniform rounded corners and soft drop shadows.

### Motion & Interaction
- Use non-user-triggered motion sparingly and deliberately, primarily to establish hierarchy or guide focus during initial load.
- One coordinated sequence or reveal makes a far stronger impression than scattered effects.
- Avoid automatic fade-and-slide-up animations on every scroll section and hover lifts on every card; these are common tells of generic generated templates.
- Prioritise responsive motion triggered by user actions (expanding, switching, confirming) that clarifies state changes. Always honour `prefers-reduced-motion`.

---

## 3. Catalog of Generic AI Tells (Anti-Patterns to Avoid)

Unless the client's brief specifically requests one of these aesthetics, consciously avoid these default generated traits:
- Warm cream background (`#F4F1EA`) with high-contrast serif headings and terracotta/clay accents (`#D97757`).
- Near-black canvas (`#0B0B0B`) with an isolated neon acid-green or hot vermilion accent.
- Broadsheet newspaper clones with hairline rules and zero border radius applied indiscriminately to non-editorial products.
- Repetitive SaaS cards: every element enclosed in identical rounded rectangles with soft grey drop shadows (`rgba(0,0,0,0.08)`) and decorative gradient washes.
- Predictable chrome: spaced all-caps tags, metadata strings separated by middle dots (`A · B · C`), or labels containing spaced em dashes.
- Appending arrows (`→`) uniformly to all links and button copy.

---

## 4. Engineering & Implementation Standards

Following the engineering practices of premier design studios and technology research organisations:
1. **Semantic CSS Custom Properties**:
   - Structure visual tokens cleanly at the root level (`--color-bg`, `--color-surface`, `--color-accent`, `--font-display`, `--space-unit`).
   - Ensures interoperability across vanilla CSS, Tailwind utility configurations, React, Vue, and Web Components.
2. **Specificity & Layout Hygiene**:
   - Maintain shallow CSS selector specificity. Avoid mixing tag-based and utility selectors that fight for margin or padding precedence.
   - Use modern CSS Grid and Flexbox for fluid, responsive layouts down to 320px viewports.
3. **Accessibility**:
   - Meet WCAG AA contrast ratios across all states.
   - Provide distinct keyboard focus rings (`:focus-visible`).
4. **Copywriting in Code**:
   - Write clear, active CTA copy (e.g. "Save changes", "Create account" rather than "Submit").
   - Interface vocabularies must remain cohesive throughout the user journey.

---

## 5. Execution Workflow: The Two-Pass Process

Always work in two distinct phases:

### Phase 1: Planning, Tokens & Layout (Interactive Checkpoint)
Before writing production markup or styles, formulate a concise design plan:
1. **Subject & Target Audience**: Confirm the core product, audience, and mood.
2. **Colour System**: A curated palette of 4 to 6 named hex values with defined functional roles.
3. **Typography System**: The chosen typefaces, scale ratios, and roles.
4. **Layout Concept & ASCII Wireframe**: Textual description of spatial relationships, alignment rules, and an ASCII structural wireframe.
5. **Self-Critique against Defaults**: Explicitly check whether any component resembles a generic AI default; revise and document why.

> **CRITICAL CHECKPOINT**:
> Present this plan to the user and pause. Confirm their approval or collect directional feedback before proceeding to Phase 2.

### Phase 2: Production Build
Once the user validates the direction:
1. Implement the solution using semantic HTML and CSS Custom Properties.
2. Ensure full mobile responsiveness, accessible interactive states, and clean code organization.
3. Review against the brief to confirm that boldness is concentrated in one memorable focal point while supporting elements remain disciplined.
