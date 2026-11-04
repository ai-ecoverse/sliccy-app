from prerequisite_image import require,integer,data,slice_row

PAIRED={'slice-apple-requirement','slice-apple-validity','slice-platform','slice-path-resolve','slice-file-open','slice-file-before',
        'slice-file-read','slice-file-after-read','slice-create','slice-info','slice-selected-validity','slice-selected-recheck',
        'slice-file-after','slice-live-recheck','slice-live-copy','slice-live-info','slice-kernel-recheck'}
SINGLES={'slice-live-identity','slice-layout','slice-candidate','slice-selection'}


def record(phase,row):
    if phase=='slice-selection':
        require(set(row)=={'accepted','reason','matchCount','selectedIndex'} and type(row['accepted']) is bool
                and integer(row['matchCount']) and 0<=row['matchCount']<=8,'slice-selection-shape')
        require(row['reason'] in {'unique-match','live-hash','live-hash-type','candidate-count','candidate-hash','candidate-hash-type','zero-match','multiple-match'},'slice-selection-reason')
        if row['accepted']:
            require(row['reason']=='unique-match' and row['matchCount']==1 and integer(row['selectedIndex']) and 0<=row['selectedIndex']<8,'slice-selection-accepted')
        else:require(row['reason']!='unique-match' and row['selectedIndex'] is None,'slice-selection-refused')
    elif phase=='slice-live-identity':
        require(set(row)=={'identifier','hash','hashType','kernelHash'} and row['identifier'] in ('ai.sliccy.mac','com.apple.WindowServer')
                and integer(row['hashType']) and 1<=row['hashType']<=4,'slice-live-shape')
        require(data(row['hash'],20,20)==data(row['kernelHash'],20,20),'slice-live-kernel')
    elif phase=='slice-candidate':
        require(set(row)=={'slice','hash','hashType','codeOffset'} and integer(row['hashType']) and 1<=row['hashType']<=4
                and integer(row['codeOffset']),'slice-candidate-shape')
        slice_row(row['slice']);data(row['hash'],20,20);require(row['codeOffset']==row['slice']['offset'],'slice-candidate-offset')
    elif phase=='slice-layout':
        require(set(row)=={'slices'} and type(row['slices']) is list and 1<=len(row['slices'])<=8,'slice-layout')
        for item in row['slices']:slice_row(item)
    elif phase in ('slice-file-before','slice-file-after'):
        require(set(row)=={'fdStatus','fdErrno','pathStatus','pathErrno','fd','path','same'} and type(row['same']) is bool,'slice-file-shape')
    elif phase in ('slice-platform','slice-path-resolve','slice-file-after-read','slice-kernel-recheck'):
        key={'slice-platform':'platformBinary','slice-path-resolve':'matchesInput','slice-file-after-read':'same','slice-kernel-recheck':'same'}[phase]
        require(type(row.get(key)) is bool,'slice-result-boolean')
