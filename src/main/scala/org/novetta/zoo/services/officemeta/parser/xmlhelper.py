"""
Totem officemeta service - xml helper library

TODO:
    - xml2obj name misleading, exchange it in all sources
"""

def normalize_tag(name):
    if name[0] == "{":
        uri, tag = name[1:].split("}")
        return uri + tag
    else:
        return name

def split_tag(name):
    if name[0] == "{":
        uri, tag = name[1:].split("}")
        return (uri, tag)
    else:
        return ("", name)

def xml2dict(xml,max_depth=1):
    return xml2obj(xml,max_depth)
def xml2obj(xml,max_depth=1):
    # identify namespace and tag
    (namespace, tag) = split_tag(xml.tag)
    # sort and grab attributes
    attribute_keys = sorted(xml.keys())
    attributes = {}
    for key in attribute_keys:
        (attr_namespace, attr_key) = split_tag(key)
        attributes[attr_key] = {
            "key":          attr_key,
            "namespace":    attr_namespace,
            "value":        xml.get(key)
        }
    
    # create dict
    r = {
        "tag":              tag,
        "namespace":        namespace,
        "attribute_keys":   attribute_keys,
        "attributes":       attributes,
        "text":             xml.text,
        "tail":             xml.tail,
    }
    
    # go over children if sufficient depth
    if len(xml) > 0:
        children = "truncated"
        if max_depth>1:
            children = []
            for child in xml:
                children.append(xml2obj(child,max_depth-1))
        r["children"] = children
    
    #
    return r
