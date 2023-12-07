scanner_signatures = [
    (['S', 'SA', 'A', 'RA'], 'Angry IP', 'Open'),
    ([('S', 1152), 'RA'], 'Angry IP', 'Closed'),
    ([('S', 64240), 'RA', ('S', 64240), 'RA'], 'Angry IP Echo Ping', 'Closed'),
    (['S', 'SA', 'R', 'R'], 'Masscan', 'Open'),
    (['S', 'RA', 'R'], 'Masscan', 'Closed'),
    ([('S', 1024), 'SA', 'R'], 'Nmap', 'Open'),
    ([('S', 1024), 'RA'], 'Nmap', 'Closed'),
    ([('S', 65535), 'SA', 'R'], 'ZMap', 'Open'),
    ([('S', 65535), 'RA'], 'ZMap', 'Closed'),
]

def signature_match(flag_sequence, signature):
    if len(flag_sequence) != len(signature):
        return False
    
    for i, flag in enumerate(flag_sequence):
        # Check if the signature at this index is a tuple (flag, window_size)
        if isinstance(signature[i], tuple):
            # Check if the flag matches and the window size matches
            if isinstance(flag, tuple):
                if flag[0] != signature[i][0] or flag[1] != signature[i][1]:
                    return False
            else:
                # signature expects a window size, but incoming flag doesn't have it
                return False
        else:
            # signature is just a flag, compare only flags
            # Extract flag from incoming packet if it's a tuple (flag, window_size)
            incoming_flag = flag[0] if isinstance(flag, tuple) else flag
            if incoming_flag != signature[i]:
                return False
    return True