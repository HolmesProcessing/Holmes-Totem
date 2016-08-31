package config

// TODO: refactor into holmes-library

import (
    "os"
    "log"
    "github.com/go-ini/ini"
    "strings"
    "reflect"
    "strconv"
)

var (
    infoLogger *log.Logger
)

func init() {
    infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
}

/*
 * Fill a struct given by a pointer via #dest with the values found at #path.
 * The INI file is expected to contain sections and as such, the provided struct
 * must have two layers:
 * type OuterStruct struct {
 *     sectionName SectionStructForSectionName
 *     sectionName2 SectionStructForSectionName2
 *     ...
 * }
 * All sections names are treated lower case, no exceptions, same applies to
 * key value pairs keys.
 * If a field in the struct (section or kv) is required, set its tag to
 * `required`. A panic will be raised if the field is not available.
 * If a value in the INI file has no corresponding entry in the struct, it is
 * ignored.
 * Please note that all values that aren't saved in a section automatically have
 * the section named "default".
 * Config options can only be strings. You'll have to do conversions yourself.
 * (For now, update for that is planned)
 *
 * @param dest Pointer to a struct containing structs, who in turn contain strings.
 * @param path Absolute or relative path to the configuration file in INI format.
 */
func Parse(dest interface{}, path string) {
    // Get the container struct:
    container   := reflect.ValueOf(dest).Elem()

    // Get the amount of contained fields then create a mapping of fields:
    sectionMapping := make(map[string]reflect.Value)
    sectionMissing := make(map[string]bool)
    for i,j:=0,container.NumField(); i<j; i++ {
        field   := container.Field(i)
        name    := strings.ToLower(container.Type().Field(i).Name)
        tag     := container.Type().Field(i).Tag
        if (field.Kind() == reflect.Ptr) {
            field = field.Elem()
        }
        sectionMapping[name]  = field
        if (tag == "required") {
            sectionMissing[name] = true
        }
    }

    // Get the mapping of section->key->value
    kvMapping := make(map[string]map[string]reflect.Value)
    kvMissing := make(map[string]map[string]bool)
    for sectionName, section := range sectionMapping {
        for i,j:=0,section.NumField(); i<j; i++ {
            field := section.Field(i)
            name  := strings.ToLower(section.Type().Field(i).Name)
            tag   := section.Type().Field(i).Tag
            if (field.Kind() == reflect.Ptr) {
                field = field.Elem()
            }
            if _,ok:=kvMapping[sectionName]; !ok {
                kvMapping[sectionName] = make(map[string]reflect.Value)
                kvMissing[sectionName] = make(map[string]bool)
            }
            kvMapping[sectionName][name] = field
            if (tag == "required") {
                kvMissing[sectionName][name] = true
            }
        }
    }

    // Read the INI file:
    inifile, err := ini.Load(path)
    if err != nil {
        infoLogger.Fatalf("Unable to read config file %s", path)
    } else {
        infoLogger.Printf("Reading config file %s\n", path)
    }

    // Get a list of all section names in the INI-File and iterate over them.
    // Convert each name to lower case and map the original name to it.
    // Also write down the found section in the sectionMissing map.
    sections := make(map[string]string)
    for _, sectionName := range inifile.SectionStrings() {
        sectionMappingKey := strings.ToLower(sectionName)
        sections[sectionMappingKey] = sectionName
        sectionMissing[sectionMappingKey] = false
        infoLogger.Printf("Found section %s (%s)\n", sectionMappingKey, sectionName)
    }

    // Go over the sectionMissing map and see if there's a section that we are
    // missing:
    for key, missing := range sectionMissing {
        if missing {
            infoLogger.Fatalf("Missing section '%s' in the config file.\n", key)
        }
    }

    // Go over the sections mapping, retrieve section from the INI file.
    // Go over all key-value pairs contained within that section, skip those
    // for which we ain't got a section or no kvMapping (which can happen).
    // All other values are written as strings to the respective field in the
    // kvMapping.
    for sectionMappingKey, sectionName := range sections {
        section := inifile.Section(sectionName)
        for _, kvName := range section.KeyStrings() {
            kvMappingKey := strings.ToLower(kvName)
            if _,exists := kvMapping[sectionMappingKey]; !exists {
                continue
            }
            if _,exists := kvMapping[sectionMappingKey][kvMappingKey]; !exists {
                continue
            }

            // Depending on the type, set the value:
            field := kvMapping[sectionMappingKey][kvMappingKey]
            if field.Type().Kind() == reflect.Slice {
                field.Set(processSliceField(field, section, kvName))
            } else {
                field.Set(processField(field, section, kvName))
            }

            // Update missing entry:
            if _,exists := kvMissing[sectionMappingKey]; !exists {
                kvMissing[sectionMappingKey] = make(map[string]bool)
            }
            kvMissing[sectionMappingKey][kvMappingKey] = false
        }
    }

    // Go over the kvMissing map and check if all required values are set.
    for sectionMappingKey, kvMissingMap := range kvMissing {
        for kvMappingKey, missing := range kvMissingMap {
            if missing {
                infoLogger.Fatalf("Missing key '%s' in section '%s' in the config file.\n",
                           kvMappingKey, sectionMappingKey)
            }
        }
    }
}

// Currently supported: []string, []int (32 bit).
// TODO: struct tags for int size, struct tags for separator, more types.
func processSliceField(field reflect.Value, section *ini.Section, kvName string) reflect.Value {
    // Prepare list:
    stringList := strings.Split(section.Key(kvName).String(), ",")
    for idx, val := range stringList {
        stringList[idx] = strings.TrimSpace(val)
    }

    // Get contained type:
    fieldKind := field.Type().Elem().Kind()

    // Handle each type differently.
    // Strings are just returned.
    if (fieldKind == reflect.String) {
        return reflect.ValueOf(stringList)
    // Ints are converted by base 10, length 32 bits.
    } else if (fieldKind == reflect.Int) {
        intList := []int{}
        for _, str := range stringList {
            i, err := strconv.ParseInt(str, 10, 32)
            if (err != nil) {
                infoLogger.Fatalln("Error parsing 32 bit integer for field " +
                            string(kvName), err)
            }
            intList = append(intList, int(i))
        }
        return reflect.ValueOf(intList)
    // Everything else should trigger an error.
    } else {
        infoLogger.Fatalln("Do not know what to do with slice of " +
                    string(fieldKind))
    }

    // Failsafe if the error fails: Empty new iface satisfying the type.
    return reflect.New(field.Type()).Elem()
}

// Currently supported: string, int.
// TODO: struct tags for int size, more types.
func processField(field reflect.Value, section *ini.Section, kvName string) reflect.Value {
    // Get contained type:
    fieldKind := field.Kind()

    // Per type treatment:
    // Strings are trimmed then assigned directly.
    if fieldKind == reflect.String {
        strVal := strings.TrimSpace(section.Key(kvName).String())
        return reflect.ValueOf(strVal)
    // Integers are converted by base 10, length 32 bits.
    } else if fieldKind == reflect.Int {
        intVal, err := section.Key(kvName).Int()
        if err != nil {
            infoLogger.Fatalf("Unable to parse %s='%s' as int.", kvName, section.Key(kvName).String())
        }
        return reflect.ValueOf(intVal)
    } else {
        infoLogger.Fatalln("Do not know what to do with type " +
                    string(fieldKind))
    }

    // Failsafe if the error fails: Empty new iface satisfying the type.
    return reflect.New(field.Type()).Elem()
}
