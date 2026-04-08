// Package i18n provides locale-aware string lookup for user-facing messages.
package i18n

import (
	"embed"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

//go:embed locales/*.json
var localeFiles embed.FS

// Localizer loads all bundled locales and resolves strings by key.
type Localizer struct {
	locales       map[string]map[string]string // locale → key → value
	defaultLocale string
}

// New creates a Localizer with the given default locale (BCP 47 tag, e.g. "en").
// If defaultLocale is empty, "en" is used.
func New(defaultLocale string) (*Localizer, error) {
	if defaultLocale == "" {
		defaultLocale = "en"
	}

	entries, err := localeFiles.ReadDir("locales")
	if err != nil {
		return nil, err
	}

	locales := make(map[string]map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := localeFiles.ReadFile("locales/" + e.Name())
		if err != nil {
			return nil, err
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		// Stem = filename without ".json"
		stem := strings.TrimSuffix(e.Name(), ".json")
		locales[stem] = m
	}

	return &Localizer{locales: locales, defaultLocale: defaultLocale}, nil
}

// T looks up key in locale, interpolates vars ({{key}} → value), and returns
// the result. Falls back to defaultLocale, then returns the raw key on miss.
func (l *Localizer) T(locale, key string, vars ...map[string]string) string {
	msg := l.lookup(locale, key)
	if len(vars) == 0 {
		return msg
	}
	for k, v := range vars[0] {
		msg = strings.ReplaceAll(msg, "{{"+k+"}}", v)
	}
	return msg
}

func (l *Localizer) lookup(locale, key string) string {
	if m, ok := l.locales[locale]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	// Fall back to default locale.
	if locale != l.defaultLocale {
		if m, ok := l.locales[l.defaultLocale]; ok {
			if v, ok := m[key]; ok {
				return v
			}
		}
	}
	return key
}

// Locale selects the best matching loaded locale from an Accept-Language header
// value per RFC 7231. Falls back to defaultLocale when no match is found.
func (l *Localizer) Locale(acceptLanguage string) string {
	if acceptLanguage == "" {
		return l.defaultLocale
	}

	type tag struct {
		lang string
		q    float64
	}

	var tags []tag
	for _, part := range strings.Split(acceptLanguage, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lang := part
		q := 1.0
		if idx := strings.Index(part, ";"); idx >= 0 {
			lang = strings.TrimSpace(part[:idx])
			qStr := strings.TrimSpace(part[idx+1:])
			qStr = strings.TrimPrefix(qStr, "q=")
			if parsed, err := strconv.ParseFloat(qStr, 64); err == nil {
				q = parsed
			}
		}
		if lang != "" && lang != "*" {
			tags = append(tags, tag{lang, q})
		}
	}

	// Sort by q descending, stable to preserve original order on tie.
	sort.SliceStable(tags, func(i, j int) bool {
		return tags[i].q > tags[j].q
	})

	for _, t := range tags {
		// Exact match.
		if _, ok := l.locales[t.lang]; ok {
			return t.lang
		}
		// Prefix match: strip subtag (e.g. "de-AT" → "de").
		if idx := strings.IndexByte(t.lang, '-'); idx > 0 {
			prefix := t.lang[:idx]
			if _, ok := l.locales[prefix]; ok {
				return prefix
			}
		}
		// zh-Hans-CN style: strip last subtag repeatedly.
		parts := strings.Split(t.lang, "-")
		for i := len(parts) - 1; i >= 2; i-- {
			candidate := strings.Join(parts[:i], "-")
			if _, ok := l.locales[candidate]; ok {
				return candidate
			}
		}
	}

	return l.defaultLocale
}
