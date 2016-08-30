package client

import (
    "github.com/antonholmquist/jason"
)

// Internal helper function to get a string from a jason.Object
func jasonGetString(o *jason.Object, key string) string {
    if o == nil || key == "" {
        return ""
    }
    v, _ := o.GetString(key)
    return v
}

// Internal helper function to get a string slice from a jason.Object
func jasonGetStringArray(o *jason.Object, key string) []string {
    if o == nil || key == "" {
        return []string{}
    }
    v, _ := o.GetStringArray(key)
    return v
}
