-- Pandoc Lua filter: table column widths, breakable code in tables, reference font.
local function esc(s)
  s = s:gsub('\\', '\\textbackslash{}')
  s = s:gsub('([{}_#%%&%$])', '\\%1')
  s = s:gsub('%^', '\\textasciicircum{}')
  s = s:gsub('~', '\\textasciitilde{}')
  return s
end

local function breakable(s)
  local out = {}
  for ch in s:gmatch('.') do
    out[#out + 1] = esc(ch) .. (ch == ' ' and '' or '\\allowbreak{}')
  end
  return table.concat(out)
end

local function is_hashy(s)
  return #s >= 36 and s:match('^[0-9a-f]+$') ~= nil
end

local function fix_code(c)
  local size = is_hashy(c.text) and '\\tcodeh ' or '\\tcode '
  local body = breakable(c.text)
  if #c.text <= 12 then body = '\\mbox{' .. body .. '}' end
  return pandoc.RawInline('latex', '{' .. size .. body .. '}')
end

local function longest_word(s)
  local m = 0
  for w in s:gmatch('[^%s_]+') do if #w > m then m = #w end end
  return m
end

function Table(t)
  local ncol = #t.colspecs
  local maxl, sum, cnt, word = {}, {}, {}, {}
  local codew = {}
  for i = 1, ncol do maxl[i], sum[i], cnt[i], word[i], codew[i] = 0, 0, 0, 0, 0 end
  local function addrow(row)
    for i, cell in ipairs(row.cells) do
      local s = pandoc.utils.stringify(cell.contents)
      local plain = pandoc.utils.stringify(pandoc.Blocks(cell.contents):walk({ Code = function() return pandoc.Str('') end }))
      local len = #s
      if is_hashy(s) then len = math.floor(len * 0.62) end
      if len > maxl[i] then maxl[i] = len end
      sum[i] = sum[i] + len
      cnt[i] = cnt[i] + 1
      cell.contents:walk({ Code = function(c) if not is_hashy(c.text) and #c.text > codew[i] then codew[i] = #c.text end end })
      local w = longest_word(plain)
      if w > word[i] then word[i] = w end
    end
  end
  for _, r in ipairs(t.head.rows) do addrow(r) end
  for _, b in ipairs(t.bodies) do for _, r in ipairs(b.body) do addrow(r) end end
  local want, total = {}, 0
  for i = 1, ncol do
    local avg = cnt[i] > 0 and sum[i] / cnt[i] or 5
    local w = 0.5 * avg + 0.5 * math.min(maxl[i], 60)
    local wm = math.min(word[i], 14) * 2.3
    if w < wm then w = wm end
    if w < 7 then w = 7 end
    want[i] = w
    total = total + w
  end
  local W = 400
  local frac, floor_, fixed = {}, {}, 0
  for i = 1, ncol do
    frac[i] = want[i] / total
    floor_[i] = (math.max(math.min(word[i], 16) * (ncol >= 8 and 4.7 or 5.3), math.min(codew[i], (ncol >= 8 and 13 or 22)) * (ncol >= 8 and 3.8 or 4.2)) + 3) / W
  end
  local free = 0
  for i = 1, ncol do
    if frac[i] < floor_[i] then frac[i] = floor_[i]; fixed = fixed + frac[i]
    else free = free + frac[i] end
  end
  for i = 1, ncol do
    if frac[i] ~= floor_[i] or frac[i] > floor_[i] then
      if frac[i] > floor_[i] then frac[i] = frac[i] * (1 - fixed) / free end
    end
    t.colspecs[i] = { t.colspecs[i][1], frac[i] }
  end
  return t:walk({ Code = fix_code })
end

function Div(d)
  if d.classes:includes('refs') then
    local out = { pandoc.RawBlock('latex', '\\begingroup\\refsfont') }
    for _, blk in ipairs(d.content) do out[#out + 1] = blk end
    out[#out + 1] = pandoc.RawBlock('latex', '\\endgroup')
    return out
  end
end
