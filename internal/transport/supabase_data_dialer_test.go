package transport

import "testing"

func TestSupabaseProjectHostIsStrict(t *testing.T) {
	for _, host := range []string{
		"abcdefghijklmnopqrst.supabase.co",
		"db.abcdefghijklmnopqrst.supabase.co",
		"abcdefghijklmnopqrstu.supabase.co",
		"abcdefghijklmnopqrst.evil.example",
	} {
		got := supabaseProjectHost.MatchString(host)
		want := host == "abcdefghijklmnopqrst.supabase.co"
		if got != want { t.Errorf("%q matched=%t, want %t", host, got, want) }
	}
}
