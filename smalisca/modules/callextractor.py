''' Smali keyword parsing functionality '''

def getArgs(arglist):
    types = ['V','Z','B','S','C','I','J','F','D']
    arglist = arglist.replace(' ','')
    arglist = arglist.replace('/','.')
    
    for i in range(0,len(arglist)):
        if i == 0:
            if arglist[i] == 'L':
                arglist = arglist[:i] + '' + arglist[i+1:]
                i -= 1
            continue
        if i == len(arglist):
            break
        
        if arglist[i] == 'L':
            if (arglist[i-1] in types):
                arglist = arglist[:i] + ';' + arglist[i+1:]
                i -= 1
                continue
            elif (arglist[i-1] == '[') or (arglist[i-1] == ';'):
                arglist = arglist[:i] + '' + arglist[i+1:]
                i -= 1
                continue
        if arglist[i] == '[' and arglist[i-1] != ';':
            arglist = arglist[:i] + ';' + arglist[i:]
            i += 1

    res = arglist.split(';')
    
    final = []
    
    for i,arg in enumerate(res):
        if '.' not in arg:
            final.append(getType(arg))
        elif arg[0] == '[':
            final.append(arg[1:] + '[]')
        elif len(arg) > 0:
            final.append(arg)
            
    sep = ','

    result = sep.join(final)
    
    if len(result) > 0:
    	if result[-1] == ',':
    		result = result[:-1]
    
    return result
            

def getType(arglist):
    end = ''
    alist = ''
    for arg in arglist:
        if arg == '[':
            end = '[]'
            continue
        elif arg == 'V':
            alist += 'void'
        elif arg == 'Z':
            alist += 'boolean'
        elif arg == 'B':
            alist += 'byte'
        elif arg == 'S':
            alist += 'short'
        elif arg == 'C':
            alist += 'char'
        elif arg == 'I':
            alist += 'int'
        elif arg == 'J':
            alist += 'long'
        elif arg == 'F':
            alist += 'float'
        elif arg == 'D':
            alist += 'double'
        
        alist += end + ','
        end = ''
    
    return alist[:-1]