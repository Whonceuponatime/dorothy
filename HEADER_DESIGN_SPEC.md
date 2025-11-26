# Header Design Specification

## Overall Dimensions

- **Height**: 72px (sweet spot between 64-80px)
- **Padding**: 16px horizontal, 12px vertical (creates breathing room)
- **Background**: Light grey (#F3F4F6) - matches website hero section feel

## Layout Structure

```
┌─────────────────────────────────────────────────────────────────┐
│ [16px]                                                      [16px]│
│                                                                    │
│ [Logo] Network Attack Simulator    [Status Badge] [Settings?]    │
│        선박 사이버 보안 솔루션 by SeaNet                           │
│                                                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Left Block (Logo + Title)

### Composition
- **Single visual line**: Logo image + "Network Attack Simulator" text
- **Logo size**: 48px height (matches text visual weight)
- **Logo position**: Left-aligned, 16px from left edge
- **Title text**: 
  - Font: Segoe UI, SemiBold, 20px
  - Color: Navy (#111827)
  - Position: Immediately after logo (8px gap)
  - Vertical alignment: Center-aligned with logo

### Tagline (below main line)
- **Text**: "선박 사이버 보안 솔루션 by SeaNet" (or English alternative)
- **Font**: Segoe UI, Regular, 12px
- **Color**: Secondary grey (#6B7280)
- **Position**: Below title, left-aligned with logo
- **Spacing**: 4px below main title line

### Visual Hierarchy
```
[Logo 48px] Network Attack Simulator  (20px, SemiBold, Navy)
            선박 사이버 보안 솔루션 by SeaNet  (12px, Regular, Grey)
```

## Right Block (Status + Actions)

### Status Badge
- **Shape**: Pill/rounded rectangle (height: 32px, padding: 8px horizontal)
- **Border radius**: 16px (fully rounded ends)
- **Position**: Right-aligned, 16px from right edge
- **Vertical alignment**: Center of header

### Status States

#### 1. Ready / Idle
- **Text**: "● Ready" or "● Idle"
- **Background**: Soft navy (#E0E7FF) or soft green (#D1FAE5)
- **Text color**: Navy (#111827) or Green (#059669)
- **Dot color**: Navy or Green (matches text)

#### 2. Attacking / Running
- **Text**: "● Attacking" or "● Running"
- **Background**: Light coral (#FEE2E2)
- **Text color**: Coral (#E45757)
- **Dot color**: Coral (#E45757)

#### 3. Error
- **Text**: "● Error"
- **Background**: Light coral (#FEE2E2)
- **Text color**: Coral (#E45757)
- **Dot color**: Coral (#E45757)

### Optional Settings Icon
- **Position**: 12px left of status badge
- **Size**: 24x24px
- **Style**: Subtle grey icon (#6B7280), changes to navy on hover
- **Action**: Opens settings/about dialog

## Spacing & Alignment

### Horizontal Spacing
- **Left edge to logo**: 16px
- **Logo to title**: 8px
- **Title to right block**: Flexible (pushes status to right)
- **Status badge to right edge**: 16px
- **Settings icon to status badge**: 12px

### Vertical Spacing
- **Top padding**: 12px
- **Logo/title line**: Center-aligned in 72px height
- **Tagline**: 4px below main line
- **Bottom padding**: 12px

### Grid Alignment
- Header left edge aligns with main content left edge (16px from window)
- Header right edge aligns with main content right edge (16px from window)
- This creates visual continuity with the rest of the UI

## Typography Details

### Main Title
- **Font**: Segoe UI
- **Weight**: SemiBold (600)
- **Size**: 20px
- **Color**: #111827 (Navy)
- **Line height**: 28px

### Tagline
- **Font**: Segoe UI
- **Weight**: Regular (400)
- **Size**: 12px
- **Color**: #6B7280 (Secondary grey)
- **Line height**: 16px

### Status Badge Text
- **Font**: Segoe UI
- **Weight**: Medium (500)
- **Size**: 13px
- **Line height**: 16px
- **Dot**: Unicode bullet (●) or custom icon

## Visual Examples

### Ready State
```
[Logo] Network Attack Simulator              [● Ready]
       선박 사이버 보안 솔루션 by SeaNet
```

### Attacking State
```
[Logo] Network Attack Simulator          [● Attacking]
       선박 사이버 보안 솔루션 by SeaNet
```

### With Settings
```
[Logo] Network Attack Simulator    [⚙] [● Ready]
       선박 사이버 보안 솔루션 by SeaNet
```

## Implementation Notes

1. **Logo Image**: Use `logo.png` at 48px height, maintain aspect ratio
2. **Status Badge**: Use Border with CornerRadius, Background color changes based on state
3. **Responsive**: If window is narrow, tagline can wrap or hide
4. **State Management**: Status badge updates when:
   - Attack starts → "Attacking"
   - Attack stops → "Ready"
   - Error occurs → "Error"
5. **Hover States**: Settings icon changes color on hover (#111827)

## Color Palette Reference

- **Navy Primary**: #111827
- **Coral/Danger**: #E45757
- **Light Background**: #F3F4F6
- **Card Background**: #FFFFFF
- **Border**: #E5E7EB
- **Text Primary**: #111827
- **Text Secondary**: #6B7280
- **Navy Badge BG**: #E0E7FF
- **Green Badge BG**: #D1FAE5
- **Coral Badge BG**: #FEE2E2

