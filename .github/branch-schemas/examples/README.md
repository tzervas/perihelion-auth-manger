# Branch Update Patterns Guide

This guide documents common branch hierarchy patterns and their use cases. Each pattern is provided with a YAML example and detailed explanation.

## Common Update Strategies

- `merge`: Preserves feature branch history, good for parent branches
- `rebase`: Maintains linear history, good for child branches
- `ff-only`: Only allows fast-forward merges, ensures clean history
- `squash`: Combines all changes into a single commit

## Branch Hierarchy Patterns

### 1. Simple Feature Development
```yaml
# pattern: simple-feature.yaml
# Use case: Basic feature development with direct relationship to main
branches:
  - name: main
    protected: true
    children: ["feature/simple"]
  
  - name: "feature/simple"
    parent: main
    update_strategy: rebase
```

### 2. Multi-Phase Development
```yaml
# pattern: multi-phase.yaml
# Use case: Large features split into phases
branches:
  - name: main
    protected: true
    children: ["feature/phase-1"]
  
  - name: "feature/phase-1"
    parent: main
    update_strategy: merge
    children: ["feature/phase-1/component-a", "feature/phase-1/component-b"]
    
  - name: "feature/phase-2"
    parent: "feature/phase-1"
    update_strategy: merge
    children: ["feature/phase-2/component-c"]
```

### 3. Parallel Feature Development
```yaml
# pattern: parallel-features.yaml
# Use case: Multiple teams working on independent features
branches:
  - name: main
    protected: true
    children: 
      - "feature/team-1"
      - "feature/team-2"
  
  - name: "feature/team-1"
    parent: main
    update_strategy: merge
    children: ["feature/team-1/task-1", "feature/team-1/task-2"]
  
  - name: "feature/team-2"
    parent: main
    update_strategy: merge
    children: ["feature/team-2/task-1"]
```

### 4. Release Branch Pattern
```yaml
# pattern: release-branches.yaml
# Use case: Managing releases with hotfixes
branches:
  - name: main
    protected: true
    children: ["develop"]
  
  - name: develop
    parent: main
    update_strategy: merge
    children: 
      - "feature/*"
      - "release/1.0"
  
  - name: "release/1.0"
    parent: develop
    update_strategy: merge
    children: ["hotfix/1.0.*"]
```

### 5. Environment-Based Pattern
```yaml
# pattern: environment-stages.yaml
# Use case: Environment promotion pipeline
branches:
  - name: main
    protected: true
    children: ["develop"]
  
  - name: develop
    parent: main
    update_strategy: merge
    children: ["staging"]
  
  - name: staging
    parent: develop
    update_strategy: ff-only
    children: ["production"]
  
  - name: production
    parent: staging
    update_strategy: ff-only
    protected: true
```

### 6. Component Integration Pattern
```yaml
# pattern: component-integration.yaml
# Use case: Multiple components merging into integration branches
branches:
  - name: main
    protected: true
    children: ["integration"]
  
  - name: integration
    parent: main
    update_strategy: merge
    children:
      - "feature/ui"
      - "feature/api"
      - "feature/db"
  
  - name: "feature/ui"
    parent: integration
    update_strategy: rebase
    children: ["feature/ui/*"]
  
  - name: "feature/api"
    parent: integration
    update_strategy: rebase
    children: ["feature/api/*"]
```

### 7. Experimental Features Pattern
```yaml
# pattern: experimental-features.yaml
# Use case: Testing experimental features with fallback
branches:
  - name: main
    protected: true
    children: ["stable", "experimental"]
  
  - name: stable
    parent: main
    update_strategy: ff-only
    protected: true
  
  - name: experimental
    parent: main
    update_strategy: merge
    children: ["feature/exp-*"]
```

## Template Variables

Branch patterns can use variables for dynamic naming:

```yaml
# Example variable usage
feature_prefix: &prefix "feature/${TEAM}/${COMPONENT}"

branches:
  - name: *prefix
    parent: main
    vars:
      TEAM: ui
      COMPONENT: navigation
```

## Complex Update Rules

### 1. Conditional Updates
```yaml
# Only update if tests pass
update_rules:
  pre_update_check: "pytest tests/"
  post_update_check: "yarn build"
```

### 2. Custom Merge Strategies
```yaml
# Custom merge strategy with specific options
update_strategy:
  type: merge
  options:
    --no-ff: true
    --strategy: recursive
    --strategy-option: theirs
```

### 3. Protected Branch Rules
```yaml
# Protected branch with review requirements
protected_rules:
  require_reviews: 2
  status_checks:
    - "CI Tests"
    - "Security Scan"
```

## Usage Examples

1. Basic Feature Development:
```bash
python update_branch_hierarchy.py \
  --schema examples/simple-feature.yaml
```

2. Multi-Team Development:
```bash
python update_branch_hierarchy.py \
  --schema examples/parallel-features.yaml \
  --template-vars TEAM=frontend \
  --template-vars COMPONENT=ui
```

3. Release Management:
```bash
python update_branch_hierarchy.py \
  --schema examples/release-branches.yaml \
  --template-vars VERSION=1.0 \
  --template-vars RELEASE_TYPE=hotfix
```

## Best Practices

1. **Branch Naming**
   - Use consistent prefixes (feature/, hotfix/, release/)
   - Include relevant identifiers (team, component, version)
   - Keep names readable and meaningful

2. **Update Strategies**
   - Use rebase for feature branches
   - Use merge for integration branches
   - Use ff-only for production/release branches

3. **Protection Rules**
   - Always protect main/master branch
   - Protect release branches
   - Consider protecting integration branches

4. **Automation**
   - Set up automated tests before updates
   - Configure post-update validations
   - Use templates for consistency

5. **Documentation**
   - Document branch purposes
   - Include update patterns in README
   - Maintain branch cleanup policies
