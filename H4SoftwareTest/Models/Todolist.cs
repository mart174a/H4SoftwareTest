﻿using System;
using System.Collections.Generic;

namespace H4SoftwareTest.Models;

public partial class Todolist
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public string Item { get; set; } = null!;

    public virtual Cpr User { get; set; } = null!;
}
